<?php

declare(strict_types=1);

use Filagora\Plugins\Archiving\Archiving;
use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\SecurityRefusal;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\Models\FindingReview;
use Filagora\PluginsSecurity\Services\AcceptedFindings;
use Filagora\PluginsSecurity\Services\FindingReviews;
use Filagora\PluginsSecurity\Support\SeriousFindingGuard;
use Filagora\PluginsSecurity\Tests\Support\TestUser;

it('accepts a finding for the plugin, with a note', function () {
    $officer = securityOfficer();
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')]);

    $review = app(FindingReviews::class)->accept($release, $scan, 'f1', $officer, ' Used by the installer ');

    expect($review->plugin_id)->toBe($release->plugin_id)
        ->and($review->fingerprint)->toBe('f1')
        ->and($review->reviewed_by_id)->toBe($officer->id)
        ->and($review->note)->toBe('Used by the installer')
        ->and(app(AcceptedFindings::class)->for($release))->toBe(['f1']);
});

it('accepts a finding once, updating the note the second time', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')]);
    $first = securityOfficer('One');
    $second = securityOfficer('Two');

    app(FindingReviews::class)->accept($release, $scan, 'f1', $first, 'first');
    app(FindingReviews::class)->accept($release, $scan, 'f1', $second, '');

    $review = FindingReview::sole();
    expect($review->reviewed_by_id)->toBe($second->id)->and($review->note)->toBeNull();
});

it('refuses a person without the key', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')]);

    expect(fn () => app(FindingReviews::class)->accept($release, $scan, 'f1', TestUser::make('Nobody')))
        ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOT_PERMITTED)
        ->and(FindingReview::count())->toBe(0);
});

it('refuses a finding that is not in the scan, or a scan of another release', function () {
    $officer = securityOfficer();
    $release = releaseWith();
    $other = releaseWith(slug: 'other');
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')]);

    expect(fn () => app(FindingReviews::class)->accept($release, $scan, 'nope', $officer))
        ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::UNKNOWN_FINDING)
        ->and(fn () => app(FindingReviews::class)->accept($other, $scan, 'f1', $officer))
        ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::UNKNOWN_FINDING)
        ->and(FindingReview::count())->toBe(0);
});

it('takes an acceptance back', function () {
    $officer = securityOfficer();
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')]);
    app(FindingReviews::class)->accept($release, $scan, 'f1', $officer);

    expect(fn () => app(FindingReviews::class)->revoke($release, 'f1', TestUser::make('Nobody')))
        ->toThrow(fn (SecurityRefused $e) => $e->reason === SecurityRefusal::NOT_PERMITTED)
        ->and(FindingReview::count())->toBe(1);

    app(FindingReviews::class)->revoke($release, 'f1', $officer);

    expect(FindingReview::count())->toBe(0);
});

it('works out the worst finding nobody has accepted', function () {
    $release = releaseWith();
    $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL, 'a'), finding(ScanSeverity::MEDIUM, 'b')]);
    $reviews = app(AcceptedFindings::class);

    expect($reviews->effectiveSeverity($release, $scan))->toBe(ScanSeverity::CRITICAL);

    FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'a']);
    expect($reviews->effectiveSeverity($release, $scan))->toBe(ScanSeverity::MEDIUM);

    FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'b']);
    expect($reviews->effectiveSeverity($release, $scan))->toBe(ScanSeverity::NONE);
});

describe('archiving', function () {
    /**
     * A plugin with a newer release and an old one, which would be archived but for its scan.
     */
    function oldReleaseWith(?ScanSeverity $severity, array $findings = [], ScanKind $kind = ScanKind::STANDARD, ScanStatus $status = ScanStatus::COMPLETED): PluginRelease
    {
        $old = releaseWith(slug: 'plug'.uniqid());
        $newer = PluginRelease::create(['plugin_id' => $old->plugin_id, 'version' => 'v2.0.0', 'zip_path' => 'x.zip', 'status' => PluginStatus::ACTIVE]);
        PluginRelease::query()->whereKey($old->id)->update(['created_at' => now()->subYears(5)]);
        PluginRelease::query()->whereKey($newer->id)->update(['created_at' => now()->subYears(4)]);

        if ($severity !== null) {
            $scan = finishedScan($old, $severity, $findings);
            $scan->update(['kind' => $kind, 'status' => $status]);
            $old->update(['latest_security_scan_id' => $scan->id]);
        }

        return $old->refresh();
    }

    function wouldArchive(PluginRelease $release): bool
    {
        $plan = app(Archiving::class)->plan(['pluginIds' => [$release->plugin_id], 'keepMonths' => 18, 'keepPerTargetLine' => false, 'wholePlugin' => false]);
        $selected = collect($plan->archiveIds);

        return $selected->contains($release->id);
    }

    it('archives an old release that was never scanned', function () {
        expect(wouldArchive(oldReleaseWith(null)))->toBeTrue();
    });

    it('keeps a release with a serious finding nobody has accepted', function () {
        expect(wouldArchive(oldReleaseWith(ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')])))->toBeFalse();
    });

    it('archives a release whose serious finding was accepted', function () {
        $release = oldReleaseWith(ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'f1')]);
        FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'f1']);

        expect(wouldArchive($release))->toBeTrue();
    });

    it('archives a release whose findings are minor', function () {
        expect(wouldArchive(oldReleaseWith(ScanSeverity::MEDIUM, [finding(ScanSeverity::MEDIUM)])))->toBeTrue();
    });

    it('follows the configured severity, and is silent when it is null', function () {
        config(['filagora-plugins-security.archive.keep_at_severity' => 'medium']);
        expect(wouldArchive(oldReleaseWith(ScanSeverity::MEDIUM, [finding(ScanSeverity::MEDIUM)])))->toBeFalse();

        config(['filagora-plugins-security.archive.keep_at_severity' => null]);
        expect(wouldArchive(oldReleaseWith(ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)])))->toBeTrue();
    });

    it('goes by a finished standard scan only', function (ScanKind $kind, ScanStatus $status) {
        expect(wouldArchive(oldReleaseWith(ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)], $kind, $status)))->toBeTrue();
    })->with([[ScanKind::LLM, ScanStatus::COMPLETED], [ScanKind::STANDARD, ScanStatus::FAILED]]);

    it('gives its reason', function () {
        $release = oldReleaseWith(ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);

        expect(app(SeriousFindingGuard::class)->reasonToKeep($release->plugin, $release))
            ->toBe('The latest scan has a finding of High or worse that nobody has accepted.');
    });
});
