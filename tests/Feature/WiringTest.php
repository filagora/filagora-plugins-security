<?php

declare(strict_types=1);

use Filagora\Core\Modules\ModuleRegistry;
use Filagora\Core\Support\GateAbilities;
use Filagora\Plugins\Archiving\ArchiveGuards;
use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\Analyzers;
use Filagora\PluginsSecurity\Analysis\Analyzers\ClamavAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\SemgrepAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\StaticPhpAnalyzer;
use Filagora\PluginsSecurity\Contracts\LlmReviewer;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Support\Config;
use Filagora\PluginsSecurity\Support\Gates;
use Filagora\PluginsSecurity\Support\NoLlmReviewer;
use Filagora\PluginsSecurity\Tests\Support\FakeAnalyzer;

it('registers itself as a module that needs core and plugins', function () {
    $module = app(ModuleRegistry::class)->get('plugins-security');

    expect($module->requires)->toBe(['core', 'plugins'])
        ->and(app(ModuleRegistry::class)->has('plugins-security'))->toBeTrue();
});

it('runs the static, ClamAV and Semgrep analyzers, in that order', function () {
    expect(array_map('get_class', app(Analyzers::class)->all()))->toBe([StaticPhpAnalyzer::class, ClamavAnalyzer::class, SemgrepAnalyzer::class]);
});

it('lets a host add an analyzer', function () {
    app(Analyzers::class)->register(new FakeAnalyzer(fn () => AnalyzerResult::completed([])));

    expect(app(Analyzers::class)->all())->toHaveCount(4);
});

it('has no language model until the host binds one', function () {
    expect(app(LlmReviewer::class))->toBeInstanceOf(NoLlmReviewer::class)
        ->and(app(LlmReviewer::class)->isConfigured())->toBeFalse()
        ->and(app(LlmReviewer::class)->model())->toBe('none')
        ->and(fn () => app(LlmReviewer::class)->complete([]))->toThrow(LogicException::class);
});

it('puts the scans on a release', function () {
    $release = releaseWith();
    $first = finishedScan($release);
    $second = finishedScan($release, ScanSeverity::LOW);
    $llm = finishedScan($release);
    $llm->update(['kind' => ScanKind::LLM]);
    $release->update(['latest_security_scan_id' => $first->id, 'quarantine_scan_id' => $second->id]);
    $release->refresh();

    expect($release->securityScans->pluck('id')->all())->toBe([$llm->id, $second->id, $first->id])
        ->and($release->latestSecurityScan->is($first))->toBeTrue()
        ->and($release->quarantineScan->is($second))->toBeTrue()
        ->and($release->latestLlmReview->is($llm))->toBeTrue();
});

it('knows what a scan found', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH), finding(ScanSeverity::HIGH, 'b')]);

    expect($scan->release->is($release))->toBeTrue()
        ->and($scan->isFinished())->toBeTrue()
        ->and($scan->findingCount(ScanSeverity::HIGH))->toBe(2)
        ->and($scan->findingCount(ScanSeverity::LOW))->toBe(0)
        ->and($scan->hasFindingAtLeast(ScanSeverity::MEDIUM))->toBeTrue()
        ->and($scan->hasFindingAtLeast(ScanSeverity::CRITICAL))->toBeFalse();

    $scan->update(['status' => ScanStatus::FAILED]);
    expect($scan->hasFindingAtLeast(ScanSeverity::LOW))->toBeFalse();

    $clean = finishedScan($release);
    expect($clean->hasFindingAtLeast(ScanSeverity::INFO))->toBeFalse()
        ->and(SecurityScan::make()->severity())->toBe(ScanSeverity::NONE);
});

it('orders severities and picks the worst', function () {
    expect(ScanSeverity::highest(['low', 'critical', 'medium']))->toBe(ScanSeverity::CRITICAL)
        ->and(ScanSeverity::highest([ScanSeverity::INFO, null, 'bogus']))->toBe(ScanSeverity::INFO)
        ->and(ScanSeverity::highest([]))->toBe(ScanSeverity::NONE)
        ->and(ScanSeverity::HIGH->isAtLeast(ScanSeverity::HIGH))->toBeTrue()
        ->and(ScanSeverity::MEDIUM->isAtLeast(ScanSeverity::HIGH))->toBeFalse()
        ->and(ScanSeverity::CRITICAL->color())->toBe('danger')
        ->and(ScanSeverity::MEDIUM->color())->toBe('warning')
        ->and(ScanSeverity::NONE->color())->toBe('success')
        ->and(ScanSeverity::LOW->label())->toBe('Low');
});

it('says which statuses are over', function () {
    expect(ScanStatus::PENDING->isFinished())->toBeFalse()
        ->and(ScanStatus::RUNNING->isFinished())->toBeFalse()
        ->and(ScanStatus::COMPLETED->isFinished())->toBeTrue()
        ->and(ScanStatus::FAILED->color())->toBe('danger')
        ->and(ScanStatus::SKIPPED->label())->toBe('Skipped');
});

it('says which triggers email whom', function () {
    expect(ScanTrigger::UPLOAD->emailsAuthorTheResult())->toBeTrue()
        ->and(ScanTrigger::MANUAL->emailsAuthorTheResult())->toBeFalse()
        ->and(ScanTrigger::UPLOAD->emailsSupportTheFinding())->toBeTrue()
        ->and(ScanTrigger::SWEEP->emailsSupportTheFinding())->toBeFalse()
        ->and(ScanTrigger::UPLOAD->emailsAuthorTheQuarantine())->toBeFalse()
        ->and(ScanTrigger::SWEEP->emailsAuthorTheQuarantine())->toBeTrue()
        ->and(ScanTrigger::BACKFILL->label())->toBe('Version backfill');
});

it('guards archiving through the plugins package', function () {
    $guards = app(ArchiveGuards::class);
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);
    $release->update(['latest_security_scan_id' => $scan->id]);

    expect($guards->reasonToKeep($release->plugin, $release->refresh()))->not->toBeNull();
});

it('defines its ability, tied to a key a host can remap', function () {
    expect(GateAbilities::keys('filagora-plugins-security.gates'))->toBe(['filagora.plugins.security']);

    config(['filagora-plugins-security.gates' => ['filagora.plugins.security' => 'ops.security']]);
    expect(Gates::key('filagora.plugins.security'))->toBe('ops.security')
        ->and(Gates::key('other'))->toBe('other');
});

it('uses the default queue unless one is named', function () {
    expect(Config::queue())->toBeNull();

    config(['filagora-plugins-security.scanner.queue' => 'scans']);
    expect(Config::queue())->toBe('scans');

    config(['filagora-plugins-security.scanner.queue' => '']);
    expect(Config::queue())->toBeNull();
});
