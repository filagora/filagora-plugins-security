<?php

declare(strict_types=1);

use Filagora\PluginsSecurity\Analysis\Analyzers\ClamavAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\SemgrepAnalyzer;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Illuminate\Contracts\Process\ProcessResult;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Process;

/**
 * A context over a real directory holding one file, so the analyzers see paths as they are in a scan.
 */
function contextFor(string $directory): ScanContext
{
    @mkdir($directory, 0700, true);
    file_put_contents($directory.'/a.php', '<?php');

    return new ScanContext(releaseWith(), $directory, $directory.'.zip');
}

function scratchDirectory(): string
{
    return sys_get_temp_dir().'/filagora-test-'.bin2hex(random_bytes(6));
}

afterEach(function () {
    foreach (glob(sys_get_temp_dir().'/filagora-test-*') ?: [] as $directory) {
        array_map('unlink', glob($directory.'/*') ?: []);
        @rmdir($directory);
    }
});

describe('ClamAV', function () {
    it('is off unless switched on, then needs a binary that answers', function () {
        Process::fake(['*' => Process::result('ClamAV 1.4.2/27142/Wed Oct 21', exitCode: 0)]);
        expect((new ClamavAnalyzer)->isAvailable())->toBeFalse();

        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        expect((new ClamavAnalyzer)->isAvailable())->toBeTrue();

        Process::fake(['*' => Process::result('', 'not found', exitCode: 127)]);
        expect((new ClamavAnalyzer)->isAvailable())->toBeFalse();
    });

    it('reports its version from the binary, or a fixed one', function () {
        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        Process::fake(['*' => Process::result('ClamAV 1.4.2/27142/Wed Oct 21 2026', exitCode: 0)]);
        expect((new ClamavAnalyzer)->version())->toBe('1.4.2/27142');

        Process::fake(['*' => Process::result('something else', exitCode: 0)]);
        expect((new ClamavAnalyzer)->version())->toBe('1');

        Process::fake(['*' => Process::result('', exitCode: 127)]);
        expect((new ClamavAnalyzer)->version())->toBe('1');
    });

    it('turns each signature hit into a critical finding at the file\'s relative path', function () {
        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        $directory = scratchDirectory();
        Process::fake(function (PendingProcess $process) use ($directory) {
            return str_contains($process->command[1] ?? '', '--version')
                ? Process::result('ClamAV 1.4.2/1', exitCode: 0)
                : Process::result("{$directory}/a.php: Php.Trojan.Agent-1 FOUND\n{$directory}/sub/b.js: Win.Test.EICAR_HDB-1 FOUND\n", exitCode: 1);
        });

        $result = (new ClamavAnalyzer)->analyze(contextFor($directory));

        expect($result->isCompleted())->toBeTrue()
            ->and($result->findings)->toHaveCount(2)
            ->and($result->findings[0]->ruleId)->toBe('clamav-phptrojanagent-1')
            ->and($result->findings[0]->severity)->toBe(ScanSeverity::CRITICAL)
            ->and($result->findings[0]->file)->toBe('a.php')
            ->and($result->findings[0]->title)->toBe('ClamAV signature match: Php.Trojan.Agent-1')
            ->and($result->findings[1]->file)->toBe('sub/b.js');
    });

    it('finds nothing in a clean archive', function () {
        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        Process::fake(['*' => Process::result('ClamAV 1.4.2/1', exitCode: 0)]);

        $result = (new ClamavAnalyzer)->analyze(contextFor(scratchDirectory()));

        expect($result->isCompleted())->toBeTrue()->and($result->findings)->toBe([]);
    });

    it('fails, saying why, when ClamAV reports an error', function () {
        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        Process::fake(function (PendingProcess $process) {
            return str_contains($process->command[1] ?? '', '--version')
                ? Process::result('ClamAV 1.4.2/1', exitCode: 0)
                : Process::result('', 'LibClamAV Error: database missing', exitCode: 2);
        });

        $result = (new ClamavAnalyzer)->analyze(contextFor(scratchDirectory()));

        expect($result->status)->toBe('failed')->and($result->note)->toBe('ClamAV error: LibClamAV Error: database missing');
    });

    it('passes the descriptor to the daemon client only', function () {
        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        Process::fake(['*' => Process::result('ClamAV 1', exitCode: 0)]);

        (new ClamavAnalyzer)->analyze(contextFor(scratchDirectory()));
        Process::assertRan(fn (PendingProcess $process) => in_array('--fdpass', (array) $process->command, true));

        Process::fake(['*' => Process::result('ClamAV 1', exitCode: 0)]);
        config(['filagora-plugins-security.analyzers.clamav.binary' => 'clamscan']);
        (new ClamavAnalyzer)->analyze(contextFor(scratchDirectory()));
        Process::assertRan(fn (PendingProcess $process) => ($process->command[0] ?? '') === 'clamscan' && ! in_array('--fdpass', (array) $process->command, true));
    });

    it('skips when no binary can be found', function () {
        config(['filagora-plugins-security.analyzers.clamav.enabled' => true]);
        Process::fake(['*' => Process::result('', exitCode: 127)]);

        $result = (new ClamavAnalyzer)->analyze(contextFor(scratchDirectory()));

        expect($result->status)->toBe('skipped')->and($result->note)->toBe('no ClamAV binary found');
    });
});

describe('Semgrep', function () {
    function semgrepOutput(array $results): ProcessResult
    {
        return Process::result(json_encode(['results' => $results]), exitCode: $results === [] ? 0 : 1);
    }

    it('is off unless switched on, then needs a binary and a ruleset', function () {
        Process::fake(['*' => Process::result('1.90.0', exitCode: 0)]);
        expect((new SemgrepAnalyzer)->isAvailable())->toBeFalse();

        config(['filagora-plugins-security.analyzers.semgrep.enabled' => true]);
        expect((new SemgrepAnalyzer)->isAvailable())->toBeTrue();

        config(['filagora-plugins-security.analyzers.semgrep.ruleset_path' => '/nonexistent/rules']);
        expect((new SemgrepAnalyzer)->isAvailable())->toBeFalse();

        config(['filagora-plugins-security.analyzers.semgrep.ruleset_path' => null]);
        Process::fake(['*' => Process::result('', exitCode: 127)]);
        expect((new SemgrepAnalyzer)->isAvailable())->toBeFalse();
    });

    it('ships rules of its own, which Semgrep is pointed at', function () {
        config(['filagora-plugins-security.analyzers.semgrep.enabled' => true]);
        Process::fake(['*' => semgrepOutput([])]);

        (new SemgrepAnalyzer)->analyze(contextFor(scratchDirectory()));

        Process::assertRan(fn (PendingProcess $process) => in_array('--config', $process->command, true)
            && is_dir($process->command[array_search('--config', $process->command, true) + 1])
            && in_array('--metrics=off', $process->command, true));
        expect(glob(__DIR__.'/../../resources/semgrep/*.yml'))->not->toBe([]);
    });

    it('versions itself by the binary and a hash of the rules, so a rule change shows', function () {
        Process::fake(['*' => Process::result('1.90.0', exitCode: 0)]);
        $directory = scratchDirectory();
        mkdir($directory);
        file_put_contents($directory.'/one.yml', 'rules: []');
        config(['filagora-plugins-security.analyzers.semgrep.ruleset_path' => $directory]);

        $before = (new SemgrepAnalyzer)->version();
        file_put_contents($directory.'/one.yml', 'rules: [a]');
        $after = (new SemgrepAnalyzer)->version();

        expect($before)->toStartWith('1.90.0/rules-')->and($after)->not->toBe($before);
    });

    it('turns matches into findings with the rule\'s message, file and line', function () {
        $directory = scratchDirectory();
        Process::fake(['*' => semgrepOutput([
            ['check_id' => 'rules.php-eval-request-data', 'path' => "{$directory}/a.php", 'start' => ['line' => 7], 'extra' => ['severity' => 'ERROR', 'message' => ' eval on request data ']],
            ['check_id' => 'plain', 'path' => 'relative.php', 'extra' => ['severity' => 'WARNING', 'message' => 'Careful']],
            ['check_id' => 'rules.other', 'path' => '', 'extra' => ['severity' => 'INFO']],
            'garbage',
        ])]);

        $result = (new SemgrepAnalyzer)->analyze(contextFor($directory));

        expect($result->findings)->toHaveCount(3)
            ->and($result->findings[0]->ruleId)->toBe('semgrep-php-eval-request-data')
            ->and($result->findings[0]->severity)->toBe(ScanSeverity::HIGH)
            ->and($result->findings[0]->title)->toBe('eval on request data')
            ->and($result->findings[0]->file)->toBe('a.php')
            ->and($result->findings[0]->line)->toBe(7)
            ->and($result->findings[1]->ruleId)->toBe('semgrep-plain')
            ->and($result->findings[1]->severity)->toBe(ScanSeverity::MEDIUM)
            ->and($result->findings[1]->file)->toBe('relative.php')
            ->and($result->findings[2]->severity)->toBe(ScanSeverity::LOW)
            ->and($result->findings[2]->file)->toBeNull();
    });

    it('maps the severities Semgrep uses', function (string $semgrep, ScanSeverity $ours) {
        Process::fake(['*' => semgrepOutput([['check_id' => 'r', 'path' => 'a.php', 'extra' => ['severity' => $semgrep, 'message' => 'm']]])]);

        expect((new SemgrepAnalyzer)->analyze(contextFor(scratchDirectory()))->findings[0]->severity)->toBe($ours);
    })->with([['ERROR', ScanSeverity::HIGH], ['high', ScanSeverity::HIGH], ['CRITICAL', ScanSeverity::HIGH], ['WARNING', ScanSeverity::MEDIUM], ['medium', ScanSeverity::MEDIUM], ['INFO', ScanSeverity::LOW], ['whatever', ScanSeverity::LOW]]);

    it('fails when Semgrep errors, or says nothing it can read', function (Closure $result, string $note) {
        Process::fake(['*' => $result()]);

        $outcome = (new SemgrepAnalyzer)->analyze(contextFor(scratchDirectory()));

        expect($outcome->status)->toBe('failed')->and($outcome->note)->toBe($note);
    })->with([
        'a fatal error' => [fn () => Process::result('', 'rules are broken', exitCode: 2), 'semgrep error: rules are broken'],
        'no json' => [fn () => Process::result('not json', exitCode: 0), 'semgrep produced no parseable JSON.'],
        'no results' => [fn () => Process::result('{"errors": []}', exitCode: 0), 'semgrep produced no parseable JSON.'],
    ]);
});
