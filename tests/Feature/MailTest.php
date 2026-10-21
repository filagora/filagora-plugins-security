<?php

declare(strict_types=1);

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Events\QuarantineCleared;
use Filagora\PluginsSecurity\Events\ReleaseQuarantined;
use Filagora\PluginsSecurity\Events\ScanFinished;
use Filagora\PluginsSecurity\Events\SeriousFindingFlagged;
use Filagora\PluginsSecurity\Notifications\SecurityNotification;
use Filagora\PluginsSecurity\Services\Quarantine;
use Filagora\PluginsSecurity\Tests\Support\TestUser;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Notification::fake();
    config(['filagora-plugins.mail.support_email' => 'support@example.test']);
});

/**
 * A release uploaded by one person for a plugin owned by another.
 *
 * @return array{0: PluginRelease, 1: TestUser, 2: TestUser}
 */
function ownedRelease(PluginStatus $status = PluginStatus::ACTIVE): array
{
    $owner = TestUser::make('Owner');
    $uploader = TestUser::make('Uploader');
    $release = releaseWith(status: $status, owner: $owner);
    $release->update(['uploaded_by_id' => $uploader->id]);

    return [$release->refresh(), $owner, $uploader];
}

function kindsSentTo(object $notifiable): array
{
    return Notification::sent($notifiable, SecurityNotification::class)->map(fn ($n) => $n->kind)->all();
}

function rendered(SecurityNotification $notification, object $to): MailMessage
{
    return $notification->toMail($to);
}

describe('the scan of an upload', function () {
    it('tells the uploader and the owner once, whatever came of it', function (ScanSeverity $severity, string $outcome) {
        [$release, $owner, $uploader] = ownedRelease();
        $scan = finishedScan($release, $severity, $severity === ScanSeverity::NONE ? [] : [finding($severity)]);

        ScanFinished::dispatch($release, $scan);

        Notification::assertSentTo([$owner, $uploader], SecurityNotification::class, function (SecurityNotification $n) use ($outcome) {
            return $n->kind === 'scan_complete' && str_contains(implode(' ', $n->details), $outcome);
        });
    })->with([
        'clean' => [ScanSeverity::NONE, 'found no problems'],
        'flagged' => [ScanSeverity::MEDIUM, '1 finding(s), the worst of them Medium'],
    ]);

    it('tells one person once when they uploaded their own plugin', function () {
        $owner = TestUser::make('Solo');
        $release = releaseWith(owner: $owner);

        ScanFinished::dispatch($release, finishedScan($release));

        Notification::assertSentToTimes($owner, SecurityNotification::class, 1);
    });

    it('says the release is held when it was quarantined', function () {
        [$release, $owner] = ownedRelease();
        $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);
        app(Quarantine::class)->evaluateAfterScan($release, $scan);

        ScanFinished::dispatch($release->refresh(), $scan);

        Notification::assertSentTo($owner, SecurityNotification::class, fn (SecurityNotification $n) => $n->kind === 'scan_complete'
            && str_contains(implode(' ', $n->details), 'held back for review')
            && str_contains(implode(' ', $n->details), 'not public while it is held'));
    });

    it('says when the scan failed', function () {
        [$release, $owner] = ownedRelease();
        $scan = finishedScan($release);
        $scan->update(['status' => ScanStatus::FAILED]);

        ScanFinished::dispatch($release, $scan);

        Notification::assertSentTo($owner, SecurityNotification::class, fn (SecurityNotification $n) => str_contains(implode(' ', $n->details), 'could not be completed'));
    });

    it('says whether the release is live or waiting', function (PluginStatus $status, string $line) {
        [$release, $owner] = ownedRelease($status);

        ScanFinished::dispatch($release, finishedScan($release));

        Notification::assertSentTo($owner, SecurityNotification::class, fn (SecurityNotification $n) => str_contains(implode(' ', $n->details), $line));
    })->with([[PluginStatus::ACTIVE, 'release is live'], [PluginStatus::MODERATED, 'waiting for a moderator']]);

    it('stays quiet for any scan but the one of an upload', function (ScanTrigger $trigger) {
        [$release] = ownedRelease();

        ScanFinished::dispatch($release, finishedScan($release, trigger: $trigger));

        Notification::assertNothingSent();
    })->with([ScanTrigger::MANUAL, ScanTrigger::RESCAN, ScanTrigger::SWEEP, ScanTrigger::BACKFILL]);
});

describe('a quarantine', function () {
    it('tells the authors when it is asked to', function () {
        [$release, $owner, $uploader] = ownedRelease();
        $scan = finishedScan($release, ScanSeverity::CRITICAL);

        ReleaseQuarantined::dispatch($release, $scan, null, true);

        Notification::assertSentTo([$owner, $uploader], SecurityNotification::class, fn (SecurityNotification $n) => $n->kind === 'quarantined'
            && in_array("Scan reference: #{$scan->id} (scanner v1).", $n->details, true));
    });

    it('can do without a scan reference', function () {
        [$release, $owner] = ownedRelease();

        ReleaseQuarantined::dispatch($release, null, securityOfficer(), true);

        Notification::assertSentTo($owner, SecurityNotification::class, fn (SecurityNotification $n) => $n->details === []);
    });

    it('says nothing when something else tells them', function () {
        [$release] = ownedRelease();

        ReleaseQuarantined::dispatch($release, finishedScan($release), null, false);

        Notification::assertNothingSent();
    });

    it('is lifted with word to the uploader only', function () {
        [$release, $owner, $uploader] = ownedRelease();

        QuarantineCleared::dispatch($release, securityOfficer());

        Notification::assertSentTo($uploader, SecurityNotification::class, fn (SecurityNotification $n) => $n->kind === 'quarantine_cleared');
        Notification::assertNotSentTo($owner, SecurityNotification::class);
    });

    it('is lifted quietly when nobody uploaded the release', function () {
        $release = releaseWith();

        QuarantineCleared::dispatch($release, null);

        Notification::assertNothingSent();
    });
});

describe('a serious finding in an upload', function () {
    it('goes to the support address, with the counts', function () {
        [$release] = ownedRelease();
        $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);

        SeriousFindingFlagged::dispatch($release, $scan);

        Notification::assertSentTo(new AnonymousNotifiable, SecurityNotification::class, function (SecurityNotification $n, array $channels, AnonymousNotifiable $notifiable) {
            return $n->kind === 'finding_flagged'
                && $notifiable->routes['mail'] === 'support@example.test'
                && $n->forStaff
                && in_array('Findings: high: 1', $n->details, true)
                && in_array('The release remains public. Review it, and quarantine it by hand if needed.', $n->details, true);
        });
    });

    it('says the release is held when it is', function () {
        [$release] = ownedRelease();
        $scan = finishedScan($release, ScanSeverity::CRITICAL, [finding(ScanSeverity::CRITICAL)]);
        app(Quarantine::class)->evaluateAfterScan($release, $scan);

        SeriousFindingFlagged::dispatch($release->refresh(), $scan);

        Notification::assertSentTo(new AnonymousNotifiable, SecurityNotification::class, fn (SecurityNotification $n) => in_array('The release has been quarantined and is hidden until it is cleared.', $n->details, true));
    });

    it('goes nowhere without a valid support address', function (?string $address) {
        config(['filagora-plugins.mail.support_email' => $address]);
        [$release] = ownedRelease();

        SeriousFindingFlagged::dispatch($release, finishedScan($release, ScanSeverity::HIGH));

        Notification::assertNothingSent();
    })->with([null, '', 'not an address']);
});

it('sends nothing at all when the mail is off', function () {
    config(['filagora-plugins-security.mail.enabled' => false]);
    [$release] = ownedRelease();
    $scan = finishedScan($release, ScanSeverity::HIGH, [finding(ScanSeverity::HIGH)]);

    ScanFinished::dispatch($release, $scan);
    ReleaseQuarantined::dispatch($release, $scan, null, true);
    QuarantineCleared::dispatch($release, null);
    SeriousFindingFlagged::dispatch($release, $scan);

    Notification::assertNothingSent();
});

describe('the email', function () {
    it('is worded from the language file, with the plugin and version', function () {
        [$release, $owner] = ownedRelease();

        $mail = rendered(new SecurityNotification('quarantine_cleared', $release, ['plugin' => 'Widget', 'version' => '1.0.0']), $owner);

        expect($mail->subject)->toBe('Security hold lifted on Widget v1.0.0')
            ->and($mail->introLines[0])->toContain('has passed review and is public again');
    });

    it('links an author to the plugin page when the route is set', function () {
        Route::get('/plugins/{plugin}', fn () => 'x')->name('plugins.show');
        Route::getRoutes()->refreshNameLookups();
        config(['filagora-plugins.routes.plugin' => 'plugins.show']);
        [$release, $owner] = ownedRelease();

        $mail = rendered(new SecurityNotification('quarantined', $release, ['plugin' => 'Widget', 'version' => '1']), $owner);

        expect($mail->actionText)->toBe('View the plugin')
            ->and($mail->actionUrl)->toEndWith('/plugins/'.$release->plugin->getRouteKey());
    });

    it('has no link when no route is set, or the dashboard is not there for staff', function () {
        [$release, $owner] = ownedRelease();

        expect(rendered(new SecurityNotification('quarantined', $release, ['plugin' => 'W', 'version' => '1']), $owner)->actionUrl)->toBeNull()
            ->and(rendered(new SecurityNotification('finding_flagged', $release, ['plugin' => 'W', 'version' => '1', 'severity' => 'High'], forStaff: true), $owner)->actionUrl)->toBeNull();
    });

    it('is queued and goes by mail', function () {
        [$release] = ownedRelease();
        $notification = new SecurityNotification('quarantined', $release);

        expect($notification)->toBeInstanceOf(ShouldQueue::class)
            ->and($notification->via(new stdClass))->toBe(['mail']);
    });
});
