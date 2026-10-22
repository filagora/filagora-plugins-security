<?php

declare(strict_types=1);

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Filament\ReleaseScreens;
use Filagora\Plugins\Filament\Resources\PluginReleases\Pages\EditPluginRelease;
use Filagora\Plugins\Filament\Resources\PluginReleases\Pages\ListPluginReleases;
use Filagora\Plugins\Filament\Resources\PluginReleases\PluginReleaseResource;
use Filagora\Plugins\Models\PluginModeratorNote;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Enums\SecurityRefusal;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\FilagoraPluginsSecurityPlugin;
use Filagora\PluginsSecurity\Filament\RelationManagers\SecurityScansRelationManager;
use Filagora\PluginsSecurity\Filament\SecurityActions;
use Filagora\PluginsSecurity\Jobs\LlmReviewJob;
use Filagora\PluginsSecurity\Jobs\ScanReleaseJob;
use Filagora\PluginsSecurity\Models\FindingReview;
use Filagora\PluginsSecurity\Notifications\SecurityNotification;
use Filagora\PluginsSecurity\Services\Quarantine;
use Filagora\PluginsSecurity\Tests\Support\FakeReviewer;
use Filagora\PluginsSecurity\Tests\Support\GrantedKeys;
use Filagora\PluginsSecurity\Tests\Support\TestUser;
use Filament\Facades\Filament;
use Filament\Notifications\Notification as FilamentNotification;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Livewire\Features\SupportTesting\Testable;
use Livewire\Livewire;

use function Pest\Laravel\actingAs;

beforeEach(function () {
    Filament::setCurrentPanel('admin');
});

/**
 * Someone who may moderate plugins and, when asked, act on security scans too.
 */
function dashboardUser(bool $security = true): TestUser
{
    $user = TestUser::make($security ? 'Sec' : 'Mod');
    app(GrantedKeys::class)->give($user, ...($security ? ['filagora.plugins.moderate', 'filagora.plugins.security'] : ['filagora.plugins.moderate']));
    actingAs($user);

    return $user;
}

/**
 * What the open action's modal shows. The test helpers do not render a modal's content, so this asks
 * the component for the schema of the action that is mounted.
 */
function modalHtml(Testable $component): string
{
    return (fn (): string => $this->getMountedActionSchema()->toHtml())->call($component->instance());
}

describe('the release list', function () {
    it('shows the scan result and version, with what a release has not been scanned for', function () {
        dashboardUser();
        $unscanned = releaseWith(slug: 'new');
        $scanned = releaseWith(slug: 'old');
        $scanned->update(['latest_security_scan_id' => finishedScan($scanned, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)], version: 1)->id]);

        Livewire::test(ListPluginReleases::class)
            ->assertTableColumnVisible('latestSecurityScan.highest_severity')
            ->assertTableColumnVisible('latestSecurityScan.scanner_version')
            ->assertTableColumnFormattedStateSet('latestSecurityScan.highest_severity', 'Not scanned', $unscanned)
            ->assertTableColumnFormattedStateSet('latestSecurityScan.highest_severity', 'High', $scanned)
            ->assertTableColumnFormattedStateSet('latestSecurityScan.scanner_version', 'v1', $scanned);
    });

    it('shows the state of a scan that did not finish, not a severity', function () {
        dashboardUser();
        $release = releaseWith();
        $scan = finishedScan($release);
        $scan->update(['status' => ScanStatus::FAILED]);
        $release->update(['latest_security_scan_id' => $scan->id]);

        Livewire::test(ListPluginReleases::class)
            ->assertTableColumnFormattedStateSet('latestSecurityScan.highest_severity', 'Failed', $release);
    });

    it('hides all of it from someone who may moderate but not act on scans', function () {
        dashboardUser(security: false);
        $release = releaseWith();
        $release->update(['latest_security_scan_id' => finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)])->id]);

        Livewire::test(ListPluginReleases::class)
            ->assertTableColumnHidden('latestSecurityScan.highest_severity')
            ->assertTableColumnHidden('latestSecurityScan.scanner_version')
            ->assertTableActionHidden('securityScan', $release)
            ->assertTableActionHidden('rescan', $release)
            ->assertTableActionHidden('quarantine', $release)
            ->assertTableBulkActionHidden('rescanSecurity')
            ->assertTableFilterHidden('security_severity')
            ->assertTableFilterHidden('security_version');
    });

    it('narrows the list by the severity of the latest scan, or to what was never scanned', function () {
        dashboardUser();
        $clean = releaseWith(slug: 'clean');
        $clean->update(['latest_security_scan_id' => finishedScan($clean)->id]);
        $bad = releaseWith(slug: 'bad');
        $bad->update(['latest_security_scan_id' => finishedScan($bad, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)])->id]);
        $never = releaseWith(slug: 'never');

        Livewire::test(ListPluginReleases::class)
            ->filterTable('security_severity', 'high')
            ->assertCanSeeTableRecords([$bad])
            ->assertCanNotSeeTableRecords([$clean, $never])
            ->filterTable('security_severity', 'none')
            ->assertCanSeeTableRecords([$clean])
            ->assertCanNotSeeTableRecords([$bad, $never])
            ->filterTable('security_severity', 'unscanned')
            ->assertCanSeeTableRecords([$never])
            ->assertCanNotSeeTableRecords([$clean, $bad]);
    });

    it('narrows the list by the scanner version, or to what is stale', function () {
        config(['filagora-plugins-security.scanner.version' => 3]);
        dashboardUser();
        $old = releaseWith(slug: 'old');
        $old->update(['latest_security_scan_id' => finishedScan($old, version: 1)->id]);
        $current = releaseWith(slug: 'current');
        $current->update(['latest_security_scan_id' => finishedScan($current, version: 3)->id]);
        $never = releaseWith(slug: 'never');

        Livewire::test(ListPluginReleases::class)
            ->filterTable('security_version', 'stale')
            ->assertCanSeeTableRecords([$old])
            ->assertCanNotSeeTableRecords([$current, $never])
            ->filterTable('security_version', '3')
            ->assertCanSeeTableRecords([$current])
            ->assertCanNotSeeTableRecords([$old, $never])
            ->filterTable('security_version', 'unscanned')
            ->assertCanSeeTableRecords([$never])
            ->assertCanNotSeeTableRecords([$old, $current]);
    });
});

describe('the latest scan', function () {
    it('opens as a modal with the findings', function () {
        dashboardUser();
        $release = releaseWith();
        $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);
        $scan->update(['analyzer_versions' => ['static_php' => ['version' => '1', 'status' => 'completed']]]);
        $release->update(['latest_security_scan_id' => $scan->id]);

        $html = modalHtml(Livewire::test(ListPluginReleases::class)->mountTableAction('securityScan', $release));

        expect($html)->toContain('Uses eval()')->toContain('a.php:1')->toContain('static_php: v1 (completed)');
    });

    it('is offered only when there is one', function () {
        dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)->assertTableActionHidden('securityScan', $release);
    });
});

describe('the AI review', function () {
    it('shows the latest one as a modal, with the model and the quoted code', function () {
        dashboardUser();
        $release = releaseWith();
        $review = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH) + ['snippet' => 'eval($x)', 'explanation' => 'Runs input.', 'suggestion' => 'Delete it.']]);
        $review->update(['kind' => ScanKind::LLM, 'analyzer_versions' => ['llm' => ['version' => 'test-model/v3-abc', 'status' => 'completed']]]);

        $component = Livewire::test(ListPluginReleases::class)->assertTableActionVisible('aiReviewResult', $release)->mountTableAction('aiReviewResult', $release);

        expect(modalHtml($component))->toContain('test-model/v3-abc')->toContain('Runs input.')->toContain('Delete it.');
    });

    it('is hidden when there is no review', function () {
        dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)->assertTableActionHidden('aiReviewResult', $release);
    });

    it('can be asked for when a model is connected, and queues a job for the person who asked', function () {
        Queue::fake();
        useReviewer(FakeReviewer::answering('[]'));
        $user = dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)
            ->assertTableActionVisible('aiReview', $release)
            ->callTableAction('aiReview', $release)
            ->assertNotified('AI review queued');

        Queue::assertPushed(LlmReviewJob::class, fn (LlmReviewJob $job) => $job->releaseId === $release->id && $job->requestedById === $user->id);
    });

    it('cannot be asked for without a model', function () {
        dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)->assertTableActionHidden('aiReview', $release);
    });
});

describe('re-scanning', function () {
    it('queues a manual scan of a release for the person who asked', function () {
        Queue::fake();
        $user = dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)
            ->callTableAction('rescan', $release)
            ->assertNotified('Security scan queued');

        Queue::assertPushed(ScanReleaseJob::class, fn (ScanReleaseJob $job) => $job->releaseId === $release->id && $job->trigger === ScanTrigger::MANUAL && $job->triggeredById === $user->id);
    });

    it('queues scans for the selected releases', function () {
        Queue::fake();
        dashboardUser();
        $one = releaseWith(slug: 'one');
        $two = releaseWith(slug: 'two');
        releaseWith(slug: 'three');

        Livewire::test(ListPluginReleases::class)
            ->callTableBulkAction('rescanSecurity', [$one, $two])
            ->assertNotified('Security scans queued');

        Queue::assertPushed(ScanReleaseJob::class, 2);
    });
});

describe('quarantine', function () {
    it('quarantines a release with a reason', function () {
        $user = dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)
            ->callTableAction('quarantine', $release, ['note' => 'Calls home'])
            ->assertNotified('Release quarantined');

        expect($release->refresh()->status)->toBe(PluginStatus::QUARANTINED)
            ->and(PluginModeratorNote::sole()->moderator_id)->toBe($user->id);
    });

    it('wants a reason', function () {
        dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)
            ->callTableAction('quarantine', $release, ['note' => ''])
            ->assertHasTableActionErrors(['note' => 'required']);

        expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE);
    });

    it('offers to quarantine what is not quarantined, and to clear what is', function () {
        dashboardUser();
        $live = releaseWith(slug: 'live');
        $held = releaseWith(slug: 'held');
        app(Quarantine::class)->quarantine($held, dashboardUser(), 'x');
        $archived = releaseWith(status: PluginStatus::ARCHIVED, slug: 'old');

        Livewire::test(ListPluginReleases::class)
            ->assertTableActionVisible('quarantine', $live)
            ->assertTableActionHidden('clearQuarantine', $live)
            ->assertTableActionHidden('quarantine', $held)
            ->assertTableActionVisible('clearQuarantine', $held)
            ->assertTableActionHidden('quarantine', $archived);
    });

    it('clears a quarantine with a resolution note', function () {
        $user = dashboardUser();
        $release = releaseWith();
        app(Quarantine::class)->quarantine($release, $user, 'x');

        Livewire::test(ListPluginReleases::class)
            ->callTableAction('clearQuarantine', $release->refresh(), ['note' => 'It is fine'])
            ->assertNotified('Quarantine cleared');

        expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE)
            ->and($release->quarantine_note)->toContain('It is fine');
    });

    it('is hidden from a person who loses the key while the page is open', function () {
        $user = dashboardUser();
        $release = releaseWith();
        $component = Livewire::test(ListPluginReleases::class);
        app(GrantedKeys::class)->give($user, 'filagora.plugins.moderate');

        $component->assertTableActionHidden('quarantine', $release);

        expect($release->refresh()->status)->toBe(PluginStatus::ACTIVE);
    });
});

describe('a refusal', function () {
    // The actions are hidden from anyone the service would refuse, so a refusal is only reachable
    // in a race; the action still has to say why and not claim success.
    function runAction(Closure $work): void
    {
        (new ReflectionMethod(SecurityActions::class, 'run'))->invoke(null, $work, 'Done');
    }

    it('is shown as a notice, not as success', function () {
        dashboardUser();

        runAction(fn () => throw new SecurityRefused(SecurityRefusal::ALREADY_QUARANTINED));

        FilamentNotification::assertNotified('This release is already quarantined.');
        FilamentNotification::assertNotNotified('Done');
    });

    it('says what was done when nothing was refused', function () {
        dashboardUser();

        runAction(fn () => null);

        FilamentNotification::assertNotified('Done');
    });
});

describe('emailing the author', function () {
    it('sends the latest result to the uploader and the owner', function () {
        Notification::fake();
        dashboardUser();
        $owner = TestUser::make('Owner');
        $release = releaseWith(owner: $owner);
        $release->update(['latest_security_scan_id' => finishedScan($release, ScanSeverity::LOW, [finding(ScanSeverity::LOW)], ScanTrigger::MANUAL)->id]);

        Livewire::test(ListPluginReleases::class)
            ->callTableAction('emailScanResultToAuthor', $release)
            ->assertNotified('Latest scan result emailed to the author');

        Notification::assertSentTo($owner, SecurityNotification::class, fn (SecurityNotification $n) => $n->kind === 'scan_complete');
    });

    it('is offered only once a scan has finished', function () {
        dashboardUser();
        $release = releaseWith();

        Livewire::test(ListPluginReleases::class)->assertTableActionHidden('emailScanResultToAuthor', $release);
    });
});

describe('the edit page', function () {
    it('lists every scan of the release, newest first', function () {
        dashboardUser();
        $release = releaseWith();
        $first = finishedScan($release, ScanSeverity::LOW, [finding(ScanSeverity::LOW)]);
        $second = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);

        Livewire::test(SecurityScansRelationManager::class, ['ownerRecord' => $release, 'pageClass' => EditPluginRelease::class])
            ->assertCanSeeTableRecords([$second, $first], inOrder: true)
            ->assertTableColumnFormattedStateSet('findings_count', 1, $second);
    });

    it('is on the page for someone who may act on scans, and not for anyone else', function () {
        $release = releaseWith();
        dashboardUser();
        expect(SecurityScansRelationManager::canViewForRecord($release, EditPluginRelease::class))->toBeTrue();

        dashboardUser(security: false);
        expect(SecurityScansRelationManager::canViewForRecord($release, EditPluginRelease::class))->toBeFalse();
    });

    it('opens a scan for reading', function () {
        dashboardUser();
        $release = releaseWith();
        $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);

        $component = Livewire::test(SecurityScansRelationManager::class, ['ownerRecord' => $release, 'pageClass' => EditPluginRelease::class])->mountTableAction('view', $scan);

        expect(modalHtml($component))->toContain('Uses eval()');
    });

    it('marks chosen findings reviewed for the plugin, so they stop counting', function () {
        $user = dashboardUser();
        $release = releaseWith();
        $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'one'), finding(ScanSeverity::LOW, 'two')]);

        Livewire::test(SecurityScansRelationManager::class, ['ownerRecord' => $release, 'pageClass' => EditPluginRelease::class])
            ->callTableAction('markFindingsReviewed', $scan, ['fingerprints' => ['one'], 'note' => 'Needed'])
            ->assertNotified('Findings marked reviewed: future scans will ignore them');

        $review = FindingReview::sole();
        expect($review->fingerprint)->toBe('one')
            ->and($review->plugin_id)->toBe($release->plugin_id)
            ->and($review->reviewed_by_id)->toBe($user->id)
            ->and($review->note)->toBe('Needed');
    });

    it('marks a finding already accepted when offering it again', function () {
        dashboardUser();
        $release = releaseWith();
        $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH, 'one')]);
        FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'one']);

        $component = Livewire::test(SecurityScansRelationManager::class, ['ownerRecord' => $release, 'pageClass' => EditPluginRelease::class])->mountTableAction('markFindingsReviewed', $scan);

        expect(modalHtml($component))->toContain('(accepted)');
    });

    it('offers to review the findings of a standard scan only, and only when it has some', function () {
        dashboardUser();
        $release = releaseWith();
        $withFindings = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);
        $clean = finishedScan($release);
        $review = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);
        $review->update(['kind' => ScanKind::LLM]);

        Livewire::test(SecurityScansRelationManager::class, ['ownerRecord' => $release, 'pageClass' => EditPluginRelease::class])
            ->assertTableActionVisible('markFindingsReviewed', $withFindings)
            ->assertTableActionHidden('markFindingsReviewed', $clean)
            ->assertTableActionHidden('markFindingsReviewed', $review);
    });

    it('filters the history', function () {
        dashboardUser();
        $release = releaseWith();
        $standard = finishedScan($release);
        $review = finishedScan($release);
        $review->update(['kind' => ScanKind::LLM]);

        Livewire::test(SecurityScansRelationManager::class, ['ownerRecord' => $release, 'pageClass' => EditPluginRelease::class])
            ->filterTable('kind', 'llm')
            ->assertCanSeeTableRecords([$review])
            ->assertCanNotSeeTableRecords([$standard]);
    });
});

it('puts the scans on the page of a release through the plugins package', function () {
    expect(PluginReleaseResource::getRelations())->toBe([SecurityScansRelationManager::class]);
});

it('adds itself once when it is on a panel twice', function () {
    $panel = Filament::getPanel('admin');
    $panel->plugin(FilagoraPluginsSecurityPlugin::make());
    FilagoraPluginsSecurityPlugin::make()->register($panel);

    expect(app(ReleaseScreens::class)->relationManagers())->toHaveCount(1);
});
