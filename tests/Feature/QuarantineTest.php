<?php

declare(strict_types=1);

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginModeratorNote;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanFinding;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Enums\SecurityRefusal;
use Filagora\PluginsSecurity\Events\QuarantineCleared;
use Filagora\PluginsSecurity\Events\ReleaseQuarantined;
use Filagora\PluginsSecurity\Events\SeriousFindingFlagged;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\Models\FindingReview;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\Quarantine;
use Filagora\PluginsSecurity\Services\Scanner;
use Filagora\PluginsSecurity\Tests\Support\FakeAnalyzer;
use Filagora\PluginsSecurity\Tests\Support\GrantedKeys;
use Filagora\PluginsSecurity\Tests\Support\TestUser;
use Illuminate\Support\Facades\Event;

function evaluate(PluginRelease $release, SecurityScan $scan): void
{
    app(Quarantine::class)->evaluateAfterScan($release->refresh(), $scan);
}

it('quarantines a release whose scan has a finding at the threshold, and remembers its status', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);

    evaluate($release, $scan);

    $release->refresh();
    expect($release->status)->toBe(PluginStatus::QUARANTINED)
        ->and($release->status_before_quarantine)->toBe('active')
        ->and($release->quarantined_at)->not->toBeNull()
        ->and($release->quarantine_scan_id)->toBe($scan->id)
        ->and($release->isQuarantined())->toBeTrue();
});

it('quarantines a release that was waiting for review, and restores it to waiting', function () {
    $release = releaseWith(status: PluginStatus::MODERATED);
    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

    expect($release->refresh()->status_before_quarantine)->toBe('moderated');

    app(Quarantine::class)->clear($release, securityOfficer(), 'false positive');

    expect($release->refresh()->status)->toBe(PluginStatus::MODERATED);
});

it('leaves a release alone below the threshold', function (ScanSeverity $severity) {
    $release = releaseWith();
    evaluate($release, finishedScan($release, $severity, [finding($severity)]));

    expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE);
})->with([ScanSeverity::INFO, ScanSeverity::LOW, ScanSeverity::MEDIUM, ScanSeverity::HIGH]);

it('follows the configured threshold', function (string $threshold, ScanSeverity $severity, PluginStatus $expected) {
    config(['filagora-plugins-security.scanner.quarantine_threshold' => $threshold]);
    $release = releaseWith();

    evaluate($release, finishedScan($release, $severity, [finding($severity)]));

    expect($release->refresh()->status)->toBe($expected);
})->with([
    ['high', ScanSeverity::HIGH, PluginStatus::QUARANTINED],
    ['high', ScanSeverity::MEDIUM, PluginStatus::ACTIVE],
    ['medium', ScanSeverity::MEDIUM, PluginStatus::QUARANTINED],
    ['info', ScanSeverity::INFO, PluginStatus::QUARANTINED],
    ['nonsense', ScanSeverity::HIGH, PluginStatus::ACTIVE],
    ['nonsense', ScanSeverity::CRITICAL, PluginStatus::QUARANTINED],
    ['none', ScanSeverity::INFO, PluginStatus::ACTIVE],
]);

it('does not look at a scan that did not complete', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);
    $scan->update(['status' => ScanStatus::FAILED]);

    evaluate($release, $scan);

    expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE);
});

it('does not count findings a moderator has accepted for the plugin', function () {
    $release = releaseWith();
    FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'accepted']);
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL, 'accepted'), finding(ScanSeverity::LOW, 'other')]);

    evaluate($release, $scan);

    expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE);
});

it('still quarantines for a finding that was not accepted', function () {
    $release = releaseWith();
    FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'accepted']);
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL, 'accepted'), finding(ScanSeverity::CRITICAL, 'new')]);

    evaluate($release, $scan);

    expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED);
});

it('only counts findings accepted for the same plugin', function () {
    $release = releaseWith();
    $other = releaseWith(slug: 'other');
    FindingReview::create(['plugin_id' => $other->plugin_id, 'fingerprint' => 'accepted']);

    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL, 'accepted')]));

    expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED);
});

it('goes by the recorded severity when a scan has no findings listed', function () {
    $release = releaseWith();

    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL));

    expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED);
});

it('only quarantines a live or waiting release', function (PluginStatus $status) {
    $release = releaseWith(status: $status);

    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

    expect($release->refresh()->status)->toBe($status);
})->with([PluginStatus::ARCHIVED, PluginStatus::REJECTED_FINAL]);

it('records why in a note on the plugin, and nothing else changes in the release', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);
    $approvedAt = $release->approved_at;

    evaluate($release, $scan);

    $note = PluginModeratorNote::query()->where('plugin_id', $release->plugin_id)->sole();
    expect($note->note)->toBe("[Release {$release->version}] Quarantined automatically by security scan #{$scan->id}: Critical finding.")
        ->and($note->moderator_id)->toBeNull()
        ->and($release->refresh()->approved_at->timestamp)->toBe($approvedAt->timestamp);
});

it('does not quarantine a release twice', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);
    evaluate($release, $scan);
    $quarantinedAt = $release->refresh()->quarantined_at;

    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)], ScanTrigger::MANUAL));

    expect($release->refresh()->status_before_quarantine)->toBe('active')
        ->and(PluginModeratorNote::count())->toBe(1)
        ->and($release->quarantined_at->timestamp)->toBe($quarantinedAt->timestamp);
});

it('announces a quarantine, telling the authors only when nothing else does', function (ScanTrigger $trigger, bool $tellAuthors) {
    Event::fake([ReleaseQuarantined::class]);
    $release = releaseWith();

    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)], $trigger));

    Event::assertDispatched(ReleaseQuarantined::class, fn (ReleaseQuarantined $event) => $event->tellAuthors === $tellAuthors && $event->moderator === null && $event->release->status === PluginStatus::QUARANTINED);
})->with([
    [ScanTrigger::UPLOAD, false],
    [ScanTrigger::BACKFILL, false],
    [ScanTrigger::MANUAL, true],
    [ScanTrigger::RESCAN, true],
    [ScanTrigger::SWEEP, true],
]);

it('tells staff of a serious finding in an upload, quarantined or not', function (ScanSeverity $severity, ScanTrigger $trigger, bool $flagged) {
    Event::fake([SeriousFindingFlagged::class]);
    $release = releaseWith();

    evaluate($release, finishedScan($release, $severity, [finding($severity)], $trigger));

    $flagged ? Event::assertDispatched(SeriousFindingFlagged::class) : Event::assertNotDispatched(SeriousFindingFlagged::class);
})->with([
    [ScanSeverity::CRITICAL, ScanTrigger::UPLOAD, true],
    [ScanSeverity::HIGH, ScanTrigger::UPLOAD, true],
    [ScanSeverity::MEDIUM, ScanTrigger::UPLOAD, false],
    [ScanSeverity::CRITICAL, ScanTrigger::SWEEP, false],
    [ScanSeverity::HIGH, ScanTrigger::MANUAL, false],
]);

it('tells staff of a finding in an upload that is already quarantined', function () {
    Event::fake([SeriousFindingFlagged::class]);
    $release = releaseWith();
    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)], ScanTrigger::MANUAL));

    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)], ScanTrigger::UPLOAD));

    Event::assertDispatchedTimes(SeriousFindingFlagged::class, 1);
});

it('lifts a quarantine when a re-scan is clean, if asked to', function () {
    config(['filagora-plugins-security.scanner.auto_clear_when_clean' => true]);
    Event::fake([QuarantineCleared::class]);
    $release = releaseWith();
    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

    evaluate($release, finishedScan($release, ScanSeverity::NONE, [], ScanTrigger::RESCAN, version: 2));

    $release->refresh();
    expect($release->status)->toBe(PluginStatus::ACTIVE)
        ->and($release->quarantined_at)->toBeNull()
        ->and($release->status_before_quarantine)->toBeNull()
        ->and($release->quarantine_cleared_at)->not->toBeNull()
        ->and($release->quarantine_cleared_by_id)->toBeNull()
        ->and($release->quarantine_note)->toContain('scanner v2');
    Event::assertDispatched(QuarantineCleared::class, fn (QuarantineCleared $event) => $event->moderator === null);
});

it('leaves a release that is not quarantined alone on a clean re-scan, even when asked to lift quarantines', function () {
    config(['filagora-plugins-security.scanner.auto_clear_when_clean' => true]);
    Event::fake([QuarantineCleared::class]);
    $release = releaseWith();

    evaluate($release, finishedScan($release, ScanSeverity::NONE, [], ScanTrigger::RESCAN));

    Event::assertNotDispatched(QuarantineCleared::class);
    expect($release->refresh()->quarantine_cleared_at)->toBeNull()->and(PluginModeratorNote::count())->toBe(0);
});

it('forgets an earlier clear when a release is quarantined again', function () {
    $officer = securityOfficer();
    $release = releaseWith();
    app(Quarantine::class)->quarantine($release, $officer, 'first');
    app(Quarantine::class)->clear($release->refresh(), $officer, 'fine');

    app(Quarantine::class)->quarantine($release->refresh(), $officer, 'again');

    $release->refresh();
    expect($release->quarantine_cleared_at)->toBeNull()
        ->and($release->quarantine_cleared_by_id)->toBeNull()
        ->and($release->quarantine_note)->toBeNull();
});

it('keeps a quarantine on a clean re-scan unless asked to lift it', function () {
    $release = releaseWith();
    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

    evaluate($release, finishedScan($release, ScanSeverity::NONE, [], ScanTrigger::RESCAN));

    expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED);
});

it('keeps a quarantine while the re-scan still has a lesser finding, even when asked to lift it on a clean one', function () {
    config(['filagora-plugins-security.scanner.auto_clear_when_clean' => true]);
    $release = releaseWith();
    evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

    evaluate($release, finishedScan($release, ScanSeverity::LOW, [finding(ScanSeverity::LOW)], ScanTrigger::RESCAN));

    expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED);
});

it('quarantines when a real scan finds something, end to end', function () {
    useAnalyzers(new FakeAnalyzer(fn () => AnalyzerResult::completed([new ScanFinding('fake', 'bad', ScanSeverity::CRITICAL, 'Very bad', 'a.php', 3, 'evil()')])));
    $release = releaseWith();

    $scan = app(Scanner::class)->scan($release, ScanTrigger::UPLOAD);

    $release->refresh();
    expect($release->status)->toBe(PluginStatus::QUARANTINED)
        ->and($release->latest_security_scan_id)->toBe($scan->id)
        ->and($release->quarantine_scan_id)->toBe($scan->id);
});

describe('by hand', function () {
    it('quarantines a release with a note, on its latest scan', function () {
        Event::fake([ReleaseQuarantined::class]);
        $officer = securityOfficer('Sam');
        $release = releaseWith();
        $scan = finishedScan($release);
        $release->update(['latest_security_scan_id' => $scan->id]);

        app(Quarantine::class)->quarantine($release, $officer, ' Looks wrong ');

        $release->refresh();
        expect($release->status)->toBe(PluginStatus::QUARANTINED)
            ->and($release->quarantine_scan_id)->toBe($scan->id)
            ->and($release->status_before_quarantine)->toBe('active');
        $note = PluginModeratorNote::sole();
        expect($note->note)->toBe("[Release {$release->version}] Quarantined by Sam: Looks wrong")
            ->and($note->moderator_id)->toBe($officer->id);
        Event::assertDispatched(ReleaseQuarantined::class, fn (ReleaseQuarantined $event) => $event->tellAuthors && $event->moderator?->is($officer));
    });

    it('quarantines a release that has never been scanned', function () {
        $release = releaseWith();

        app(Quarantine::class)->quarantine($release, securityOfficer(), 'On a hunch');

        expect($release->refresh()->quarantine_scan_id)->toBeNull()->and($release->status)->toBe(PluginStatus::QUARANTINED);
    });

    it('clears a quarantine with a note and restores the status', function () {
        Event::fake([QuarantineCleared::class]);
        $officer = securityOfficer('Sam');
        $release = releaseWith();
        evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

        app(Quarantine::class)->clear($release->refresh(), $officer, 'Checked by hand');

        $release->refresh();
        expect($release->status)->toBe(PluginStatus::ACTIVE)
            ->and($release->quarantined_at)->toBeNull()
            ->and($release->quarantine_cleared_by_id)->toBe($officer->id)
            ->and($release->quarantine_note)->toBe('Quarantine cleared by Sam: Checked by hand')
            ->and(PluginModeratorNote::count())->toBe(2);
        Event::assertDispatched(QuarantineCleared::class, fn (QuarantineCleared $event) => $event->moderator?->is($officer));
    });

    it('restores a waiting release to waiting if its status was lost', function () {
        $release = releaseWith();
        evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));
        $release->forceFill(['status_before_quarantine' => null])->save();

        app(Quarantine::class)->clear($release->refresh(), securityOfficer(), 'ok');

        expect($release->refresh()->status)->toBe(PluginStatus::MODERATED);
    });

    it('refuses a person without the key', function () {
        $release = releaseWith();

        expect(fn () => app(Quarantine::class)->quarantine($release, TestUser::make('Nobody'), 'x'))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOT_PERMITTED);
        expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE);
    });

    it('refuses a clear from a person without the key', function () {
        $release = releaseWith();
        evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

        expect(fn () => app(Quarantine::class)->clear($release->refresh(), TestUser::make('Nobody'), 'x'))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOT_PERMITTED);
        expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED);
    });

    it('wants a reason', function (string $note) {
        $release = releaseWith();

        expect(fn () => app(Quarantine::class)->quarantine($release, securityOfficer(), $note))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOTE_REQUIRED);
    })->with(['', '   ']);

    it('wants a reason to clear', function () {
        $release = releaseWith();
        evaluate($release, finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]));

        expect(fn () => app(Quarantine::class)->clear($release->refresh(), securityOfficer(), ' '))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOTE_REQUIRED);
    });

    it('will not quarantine twice, or an archived release, or clear what is not quarantined', function () {
        $officer = securityOfficer();
        $release = releaseWith();
        $archived = releaseWith(status: PluginStatus::ARCHIVED, slug: 'old');

        expect(fn () => app(Quarantine::class)->clear($release, $officer, 'x'))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOT_QUARANTINED)
            ->and(fn () => app(Quarantine::class)->quarantine($archived, $officer, 'x'))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOT_QUARANTINABLE);

        app(Quarantine::class)->quarantine($release, $officer, 'x');

        expect(fn () => app(Quarantine::class)->quarantine($release->refresh(), $officer, 'again'))
            ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::ALREADY_QUARANTINED);
    });

    it('can be remapped to another access key', function () {
        config(['filagora-plugins-security.gates' => ['filagora.plugins.security' => 'operator.plugin.security']]);
        $user = TestUser::make('Op');
        app(GrantedKeys::class)->give($user, 'operator.plugin.security');

        app(Quarantine::class)->quarantine(releaseWith(), $user, 'ok');

        expect(SecurityScan::count())->toBe(0)->and(PluginModeratorNote::count())->toBe(1);
    });
});
