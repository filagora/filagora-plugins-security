<?php

declare(strict_types=1);

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Events\ReleaseSubmitted;
use Filagora\Plugins\Release\ReleaseInput;
use Filagora\Plugins\Services\Releases;
use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanInterrupted;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Jobs\ScanReleaseJob;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Tests\Support\FakeAnalyzer;
use Filagora\PluginsSecurity\Tests\Support\GrantedKeys;
use Filagora\PluginsSecurity\Tests\Support\TestUser;
use Filagora\PluginsSecurity\Tests\Support\Zips;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Process\Exception\ProcessSignaledException;
use Symfony\Component\Process\Process;

describe('on submission', function () {
    it('queues a scan of the new release when switched on', function () {
        config(['filagora-plugins-security.scanner.dispatch_on_upload' => true, 'filagora-plugins-security.scanner.queue' => 'security']);
        Queue::fake();
        $submitter = TestUser::make('Sub');
        $release = releaseWith();

        ReleaseSubmitted::dispatch($release->plugin, $release, $submitter);

        Queue::assertPushedOn('security', ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->releaseId === $release->id
            && $job->trigger === ScanTrigger::UPLOAD
            && $job->triggeredById === $submitter->id);
    });

    it('queues on the default queue when none is named', function () {
        config(['filagora-plugins-security.scanner.dispatch_on_upload' => true]);
        Queue::fake();
        $release = releaseWith();

        ReleaseSubmitted::dispatch($release->plugin, $release, TestUser::make('Sub'));

        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->queue === null);
    });

    it('queues nothing when switched off', function () {
        Queue::fake();
        $release = releaseWith();

        ReleaseSubmitted::dispatch($release->plugin, $release, TestUser::make('Sub'));

        Queue::assertNotPushed(ScanReleaseJob::class);
    });

    it('scans a release a plugin author really submits', function () {
        config(['filagora-plugins-security.scanner.dispatch_on_upload' => true]);
        useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([])));
        Storage::fake('local');
        config(['filagora-plugins.storage.disk' => 'local']);
        $author = TestUser::make('Author');
        $moderator = TestUser::make('Mod');
        app(GrantedKeys::class)->give($author, 'filagora.plugins.auto_publish');

        $release = app(Releases::class)->submitPlugin(
            $author,
            ['name' => 'Gadget', 'plugin_type_id' => pluginType()->id],
            new ReleaseInput('1.0.0', Zips::make(), 'First', false, []),
        );

        $scan = SecurityScan::sole();
        expect($scan->plugin_release_id)->toBe($release->id)
            ->and($scan->triggered_by)->toBe(ScanTrigger::UPLOAD)
            ->and($scan->triggered_by_user_id)->toBe($author->id)
            ->and($release->refresh()->latest_security_scan_id)->toBe($scan->id);
    });
});

describe('the job', function () {
    it('scans the release', function () {
        useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([])));
        $officer = securityOfficer();
        $release = releaseWith();

        ScanReleaseJob::dispatchSync($release->id, ScanTrigger::MANUAL, $officer->id);

        $scan = SecurityScan::sole();
        expect($scan->triggered_by)->toBe(ScanTrigger::MANUAL)
            ->and($scan->triggered_by_user_id)->toBe($officer->id)
            ->and($scan->queued_at)->not->toBeNull();
    });

    it('does nothing for a release that has gone', function () {
        ScanReleaseJob::dispatchSync(999999);

        expect(SecurityScan::count())->toBe(0);
    });

    it('records a failed scan if it dies', function () {
        $release = releaseWith();

        (new ScanReleaseJob($release->id, ScanTrigger::SWEEP))->failed(new RuntimeException('out of memory'));

        $scan = SecurityScan::sole();
        expect($scan->status)->toBe(ScanStatus::FAILED)
            ->and($scan->kind)->toBe(ScanKind::STANDARD)
            ->and($scan->triggered_by)->toBe(ScanTrigger::SWEEP)
            ->and($scan->error)->toBe('The scan job failed: out of memory')
            ->and($release->refresh()->latest_security_scan_id)->toBe($scan->id);
    });

    it('records no failed scan when the worker was only told to stop', function () {
        (new ScanReleaseJob(releaseWith()->id))->failed(new ScanInterrupted('stop'));

        expect(SecurityScan::count())->toBe(0);
    });

    it('swallows an interruption, leaving no scan', function () {
        $process = Mockery::mock(Process::class);
        $process->allows('getTermSignal')->andReturn(2);
        $process->allows('getCommandLine')->andReturn('scan');
        useAnalyzers(new FakeAnalyzer(fn () => throw new ProcessSignaledException($process)));

        ScanReleaseJob::dispatchSync(releaseWith()->id);

        expect(SecurityScan::count())->toBe(0);
    });

    it('does not run twice at once for a release, and has a time limit', function () {
        config(['filagora-plugins-security.scanner.timeout_seconds' => 90]);
        $job = new ScanReleaseJob(5);

        expect($job->timeout)->toBe(90)
            ->and($job->tries)->toBe(1)
            ->and($job->middleware()[0])->toBeInstanceOf(WithoutOverlapping::class);
    });
});

describe('the sweep', function () {
    beforeEach(fn () => Queue::fake());

    function staleSetup(): array
    {
        config(['filagora-plugins-security.scanner.version' => 2]);
        $never = releaseWith(slug: 'never');
        $old = releaseWith(slug: 'old');
        $old->update(['latest_security_scan_id' => finishedScan($old, version: 1)->id]);
        $current = releaseWith(slug: 'current');
        $current->update(['latest_security_scan_id' => finishedScan($current, version: 2)->id]);
        $waiting = releaseWith(status: PluginStatus::MODERATED, slug: 'waiting');
        $archived = releaseWith(status: PluginStatus::ARCHIVED, slug: 'archived');

        return compact('never', 'old', 'current', 'waiting', 'archived');
    }

    it('queues scans for active releases never scanned or scanned by an older version', function () {
        $r = staleSetup();

        $this->artisan('filagora:plugins:security-sweep')->assertSuccessful();

        Queue::assertPushed(ScanReleaseJob::class, 2);
        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->releaseId === $r['never']->id && $job->trigger === ScanTrigger::SWEEP);
        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->releaseId === $r['old']->id);
    });

    it('takes a small batch, oldest first', function () {
        $r = staleSetup();
        config(['filagora-plugins-security.sweep.batch_size' => 1]);

        $this->artisan('filagora:plugins:security-sweep')->assertSuccessful();

        Queue::assertPushed(ScanReleaseJob::class, 1);
        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->releaseId === $r['never']->id);
    });

    it('takes a limit from the command line', function () {
        staleSetup();

        $this->artisan('filagora:plugins:security-sweep --limit=2')->assertSuccessful();

        Queue::assertPushed(ScanReleaseJob::class, 2);
    });

    it('does nothing when it is switched off', function () {
        staleSetup();
        config(['filagora-plugins-security.sweep.enabled' => false]);

        $this->artisan('filagora:plugins:security-sweep')->expectsOutput('The sweep is switched off.')->assertSuccessful();

        Queue::assertNothingPushed();
    });

    it('says when nothing is due', function () {
        $this->artisan('filagora:plugins:security-sweep')->expectsOutput('No releases are due for a scan.')->assertSuccessful();
    });

    it('lists what it would queue on a dry run', function () {
        $r = staleSetup();

        $this->artisan('filagora:plugins:security-sweep --dry-run')->expectsOutput("Would queue release #{$r['never']->id}")->assertSuccessful();

        Queue::assertNothingPushed();
    });
});

describe('the scan command', function () {
    beforeEach(fn () => Queue::fake());

    function ids(): array
    {
        return Queue::pushed(ScanReleaseJob::class)->map(fn (ScanReleaseJob $job) => $job->releaseId)->sort()->values()->all();
    }

    it('queues scans for active releases by default, as a re-scan', function () {
        $active = releaseWith();
        releaseWith(status: PluginStatus::MODERATED, slug: 'waiting');

        $this->artisan('filagora:plugins:security-scan')->assertSuccessful();

        expect(ids())->toBe([$active->id]);
        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->trigger === ScanTrigger::RESCAN);
    });

    it('filters by release, plugin slug or id, and status', function () {
        $a = releaseWith(slug: 'alpha');
        $b = releaseWith(slug: 'beta');
        $c = releaseWith(status: PluginStatus::MODERATED, slug: 'gamma');

        $this->artisan("filagora:plugins:security-scan --release={$a->id}")->assertSuccessful();
        expect(ids())->toBe([$a->id]);

        Queue::fake();
        $this->artisan('filagora:plugins:security-scan --plugin=beta')->assertSuccessful();
        expect(ids())->toBe([$b->id]);

        Queue::fake();
        $this->artisan("filagora:plugins:security-scan --plugin={$a->plugin_id}")->assertSuccessful();
        expect(ids())->toBe([$a->id]);

        Queue::fake();
        $this->artisan('filagora:plugins:security-scan --status=moderated')->assertSuccessful();
        expect(ids())->toBe([$c->id]);

        Queue::fake();
        $this->artisan('filagora:plugins:security-scan --status=any')->assertSuccessful();
        expect(ids())->toBe([$a->id, $b->id, $c->id]);

        Queue::fake();
        $this->artisan('filagora:plugins:security-scan --all')->assertSuccessful();
        expect(ids())->toBe([$a->id, $b->id, $c->id]);
    });

    it('can pick the releases never scanned, or stale, or limit them', function () {
        config(['filagora-plugins-security.scanner.version' => 2]);
        $never = releaseWith(slug: 'never');
        $old = releaseWith(slug: 'old');
        $old->update(['latest_security_scan_id' => finishedScan($old, version: 1)->id]);
        $current = releaseWith(slug: 'current');
        $current->update(['latest_security_scan_id' => finishedScan($current, version: 2)->id]);

        $this->artisan('filagora:plugins:security-scan --never-scanned')->assertSuccessful();
        expect(ids())->toBe([$never->id]);

        Queue::fake();
        $this->artisan('filagora:plugins:security-scan --stale')->assertSuccessful();
        expect(ids())->toBe([$never->id, $old->id]);

        Queue::fake();
        $this->artisan('filagora:plugins:security-scan --limit=1')->assertSuccessful();
        expect(ids())->toHaveCount(1);
    });

    it('takes the trigger from the command line, and refuses a bad one', function () {
        releaseWith();

        $this->artisan('filagora:plugins:security-scan --trigger=backfill')->assertSuccessful();
        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->trigger === ScanTrigger::BACKFILL);

        $this->artisan('filagora:plugins:security-scan --trigger=nonsense')->assertFailed();
    });

    it('says when nothing matches', function () {
        $this->artisan('filagora:plugins:security-scan')->expectsOutput('No matching releases.')->assertSuccessful();
    });

    it('lists what it would scan on a dry run', function () {
        $release = releaseWith();

        $this->artisan('filagora:plugins:security-scan --dry-run')->expectsOutputToContain("#{$release->id} widget {$release->version}")->assertSuccessful();

        Queue::assertNothingPushed();
    });

    it('scans here and now with --sync', function () {
        useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([])));
        $release = releaseWith();

        $this->artisan('filagora:plugins:security-scan --sync')->expectsOutputToContain("#{$release->id} widget {$release->version}: completed / none")->assertSuccessful();

        Queue::assertNothingPushed();
        expect(SecurityScan::sole()->triggered_by)->toBe(ScanTrigger::RESCAN);
    });

    it('stops when the worker is told to stop during a --sync scan', function () {
        $process = Mockery::mock(Process::class);
        $process->allows('getTermSignal')->andReturn(15);
        $process->allows('getCommandLine')->andReturn('scan');
        useAnalyzers(new FakeAnalyzer(fn () => throw new ProcessSignaledException($process)));
        releaseWith();
        releaseWith(slug: 'second');

        $this->artisan('filagora:plugins:security-scan --sync')->expectsOutputToContain('interrupted by a shutdown signal')->assertSuccessful();

        expect(SecurityScan::count())->toBe(0);
    });

    describe('--prune', function () {
        it('keeps the latest scan, the one behind a quarantine, and the newest of each version', function () {
            $release = releaseWith();
            $v1a = finishedScan($release, version: 1);
            $v1b = finishedScan($release, version: 1);
            $v2a = finishedScan($release, version: 2);
            $v2b = finishedScan($release, version: 2);
            $v3 = finishedScan($release, version: 3);
            $llm = finishedScan($release, version: 1);
            $llm->update(['kind' => ScanKind::LLM]);
            $release->update(['latest_security_scan_id' => $v3->id, 'quarantine_scan_id' => $v1a->id]);

            $this->artisan('filagora:plugins:security-scan --prune')->expectsOutput('Pruned 1 redundant scan(s).')->assertSuccessful();

            // Newest first: v3 (latest), v2b (newest of 2), v2a (goes), v1b (newest of 1), v1a (behind the quarantine).
            expect(SecurityScan::pluck('id')->sort()->values()->all())->toBe(collect([$v1a->id, $v1b->id, $v2b->id, $v3->id, $llm->id])->sort()->values()->all());
        });

        it('reports what it would delete on a dry run, and honours a limit', function () {
            $release = releaseWith();
            foreach ([1, 1, 1, 1] as $version) {
                finishedScan($release, version: $version);
            }
            $release->update(['latest_security_scan_id' => SecurityScan::max('id')]);

            $this->artisan('filagora:plugins:security-scan --prune --dry-run')->expectsOutput('Would delete 3 redundant scan(s).')->assertSuccessful();
            expect(SecurityScan::count())->toBe(4);

            $this->artisan('filagora:plugins:security-scan --prune --limit=1')->expectsOutput('Pruned 1 redundant scan(s).')->assertSuccessful();
            expect(SecurityScan::count())->toBe(3);
        });

        it('says when there is nothing to prune', function () {
            $this->artisan('filagora:plugins:security-scan --prune')->expectsOutput('Nothing to prune.')->assertSuccessful();
        });
    });
});
