<?php

declare(strict_types=1);

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanFinding;
use Filagora\PluginsSecurity\Analysis\ScanInterrupted;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Events\ScanFinished;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\Scanner;
use Filagora\PluginsSecurity\Tests\Support\FakeAnalyzer;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Process\Exception\ProcessSignaledException;
use Symfony\Component\Process\Process;

function scan(PluginRelease $release, ScanTrigger $trigger = ScanTrigger::MANUAL): SecurityScan
{
    return app(Scanner::class)->scan($release, $trigger);
}

it('records a clean scan and points the release at it', function () {
    useStaticAnalyzerOnly();
    $release = releaseWith(['widget/index.php' => "<?php\necho 'hello';\n"]);

    $scan = scan($release);

    expect($scan->status)->toBe(ScanStatus::COMPLETED)
        ->and($scan->kind)->toBe(ScanKind::STANDARD)
        ->and($scan->severity())->toBe(ScanSeverity::NONE)
        ->and($scan->scanner_version)->toBe(1)
        ->and($scan->triggered_by)->toBe(ScanTrigger::MANUAL)
        ->and($scan->finished_at)->not->toBeNull()
        ->and($release->refresh()->latest_security_scan_id)->toBe($scan->id)
        ->and($release->status)->toBe(PluginStatus::ACTIVE);
});

it('records who asked for the scan and when it was queued', function () {
    useStaticAnalyzerOnly();
    $officer = securityOfficer();
    $queued = now()->subMinute();

    $scan = app(Scanner::class)->scan(releaseWith(), ScanTrigger::MANUAL, $officer, $queued);

    expect($scan->triggered_by_user_id)->toBe($officer->id)
        ->and($scan->queued_at->timestamp)->toBe($queued->timestamp);
});

it('counts findings by severity and records the worst', function () {
    useStaticAnalyzerOnly();
    $release = releaseWith(['widget/a.php' => "<?php\neval(\$x);\nexec('ls');\n", 'widget/b.phar' => 'x']);

    $scan = scan($release);

    expect($scan->severity())->toBe(ScanSeverity::HIGH)
        ->and($scan->finding_counts)->toBe(['high' => 3])
        ->and(collect($scan->findings)->pluck('rule_id')->sort()->values()->all())->toBe(['eval-construct', 'exec-call', 'phar-archive']);
});

it('records every analyzer with its version, and what it did', function () {
    useAnalyzers(
        new FakeAnalyzer(fn () => AnalyzerResult::completed([]), name: 'one'),
        new FakeAnalyzer(fn () => AnalyzerResult::skipped('no thanks'), name: 'two'),
        new FakeAnalyzer(fn () => AnalyzerResult::completed([]), available: false, name: 'three'),
    );

    $scan = scan(releaseWith());

    expect($scan->analyzer_versions)->toBe([
        'one' => ['version' => '9', 'status' => 'completed'],
        'two' => ['version' => '9', 'status' => 'skipped', 'note' => 'no thanks'],
        'three' => ['version' => '9', 'status' => 'skipped', 'note' => 'unavailable'],
    ]);
});

it('does not run an analyzer that is unavailable', function () {
    $unavailable = new FakeAnalyzer(fn () => AnalyzerResult::completed([]), available: false);
    useAnalyzers($unavailable);

    scan(releaseWith());

    expect($unavailable->runs)->toBe(0);
});

it('survives an analyzer that throws, as long as another completed', function () {
    useAnalyzers(
        new FakeAnalyzer(fn () => throw new RuntimeException('boom'), name: 'bad'),
        new FakeAnalyzer(fn () => AnalyzerResult::completed([]), name: 'good'),
    );

    $scan = scan(releaseWith());

    expect($scan->status)->toBe(ScanStatus::COMPLETED)
        ->and($scan->analyzer_versions['bad']['status'])->toBe('failed')
        ->and($scan->error)->toBeNull();
});

it('fails the scan when every analyzer failed', function () {
    useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::failed('no luck'), name: 'bad'));

    $scan = scan(releaseWith());

    expect($scan->status)->toBe(ScanStatus::FAILED)
        ->and($scan->error)->toBe('Every analyzer failed.');
});

it('does not call a scan failed when its analyzers were only skipped', function () {
    useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::skipped('later')));

    expect(scan(releaseWith())->status)->toBe(ScanStatus::COMPLETED);
});

it('records a failed scan when the archive is missing', function () {
    useStaticAnalyzerOnly();
    $release = releaseWith();
    Storage::disk('local')->delete($release->zip_path);

    $scan = scan($release);

    expect($scan->status)->toBe(ScanStatus::FAILED)
        ->and($scan->error)->toBe('The release archive was not found.')
        ->and($release->refresh()->latest_security_scan_id)->toBe($scan->id);
});

it('records a failed scan for an archive that tries to leave its directory', function () {
    useStaticAnalyzerOnly();
    $release = releaseWith(['../evil.php' => '<?php']);

    $scan = scan($release);

    expect($scan->status)->toBe(ScanStatus::FAILED)
        ->and($scan->error)->toContain('unsafe path');
});

it('refuses an archive with more entries than allowed', function () {
    useStaticAnalyzerOnly();
    config(['filagora-plugins.archive.max_entries' => 2]);

    $scan = scan(releaseWith(['a/1.txt' => '1', 'a/2.txt' => '2', 'a/3.txt' => '3']));

    expect($scan->status)->toBe(ScanStatus::FAILED)
        ->and($scan->error)->toContain('too many entries');
});

it('refuses an archive that is too large once unpacked', function () {
    useStaticAnalyzerOnly();
    config(['filagora-plugins.archive.max_uncompressed_bytes' => 10]);

    $scan = scan(releaseWith(['a/big.txt' => str_repeat('x', 100)]));

    expect($scan->status)->toBe(ScanStatus::FAILED)
        ->and($scan->error)->toContain('too large');
});

it('leaves nothing behind in the temporary directory', function () {
    useStaticAnalyzerOnly();
    $before = glob(sys_get_temp_dir().'/filagora-scan-*') ?: [];

    scan(releaseWith(['widget/a.php' => '<?php echo 1;']));
    scan(releaseWith(['../evil.php' => '<?php'], slug: 'other'));

    expect(glob(sys_get_temp_dir().'/filagora-scan-*') ?: [])->toBe($before);
});

it('stores strings that are not valid UTF-8', function () {
    useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([
        new ScanFinding('fake', 'rule', ScanSeverity::LOW, "bad \xB1 bytes", 'a.php', 1, "snippet \xFF"),
    ])));

    $scan = scan(releaseWith());

    expect($scan->status)->toBe(ScanStatus::COMPLETED)
        ->and($scan->findings[0]['title'])->toContain('bad');
});

it('keeps a stored string within bounds', function () {
    useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([
        new ScanFinding('fake', 'rule', ScanSeverity::LOW, str_repeat('é', 30000)),
    ])));

    $title = scan(releaseWith())->findings[0]['title'];

    expect(mb_strlen($title))->toBe(20000 + mb_strlen('… [truncated]'))
        ->and($title)->toEndWith('… [truncated]');
});

it('caps the findings it stores but counts them all', function () {
    useAnalyzers(new FakeAnalyzer(function () {
        return AnalyzerResult::completed(array_map(
            fn (int $i) => new ScanFinding('fake', 'rule-'.$i, ScanSeverity::LOW, 'Finding '.$i),
            range(1, 5003),
        ));
    }));

    $scan = scan(releaseWith());
    $findings = $scan->findings;

    expect($findings)->toHaveCount(5000)
        ->and($scan->finding_counts)->toBe(['low' => 5003])
        ->and(end($findings)['rule_id'])->toBe('findings-truncated')
        ->and(end($findings)['title'])->toBe('4 further finding(s) omitted: the result is capped at 5000.');
});

it('records nothing when the worker is told to stop, and rethrows', function () {
    $process = Mockery::mock(Process::class);
    $process->allows('getTermSignal')->andReturn(15);
    $process->allows('getCommandLine')->andReturn('scan');
    useAnalyzers(new FakeAnalyzer(fn () => throw new ProcessSignaledException($process)));
    $release = releaseWith();

    expect(fn () => scan($release))->toThrow(ScanInterrupted::class)
        ->and(SecurityScan::count())->toBe(0)
        ->and($release->refresh()->latest_security_scan_id)->toBeNull();
});

it('treats another signal as a failed analyzer, not an interruption', function () {
    $process = Mockery::mock(Process::class);
    $process->allows('getTermSignal')->andReturn(9);
    $process->allows('getCommandLine')->andReturn('scan');
    useAnalyzers(new FakeAnalyzer(fn () => throw new ProcessSignaledException($process)));

    expect(scan(releaseWith())->status)->toBe(ScanStatus::FAILED);
});

it('announces a finished scan once the release has been dealt with', function () {
    Event::fake([ScanFinished::class]);
    useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([])));
    $release = releaseWith();

    $scan = scan($release);

    Event::assertDispatched(ScanFinished::class, fn (ScanFinished $event) => $event->scan->is($scan) && $event->release->is($release));
});

it('announces a failed scan too', function () {
    Event::fake([ScanFinished::class]);
    useStaticAnalyzerOnly();
    $release = releaseWith();
    Storage::disk('local')->delete($release->zip_path);

    scan($release);

    Event::assertDispatched(ScanFinished::class, 1);
});

it('scans an archive on a disk that is not local', function () {
    useStaticAnalyzerOnly();
    $release = releaseWith(['widget/a.php' => '<?php exit(1); eval($x);']);
    // A disk the scanner cannot read in place: faked locally, but configured as a remote driver.
    Storage::fake('remote');
    Storage::disk('remote')->put($release->zip_path, Storage::disk('local')->get($release->zip_path));
    config(['filesystems.disks.remote.driver' => 's3', 'filagora-plugins.storage.disk' => 'remote']);

    $scan = scan($release);

    expect($scan->status)->toBe(ScanStatus::COMPLETED)
        ->and(collect($scan->findings)->pluck('rule_id')->all())->toContain('eval-construct');
});
