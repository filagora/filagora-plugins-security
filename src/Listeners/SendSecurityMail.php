<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Listeners;

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Support\Users;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Events\LlmReviewFinished;
use Filagora\PluginsSecurity\Events\QuarantineCleared;
use Filagora\PluginsSecurity\Events\ReleaseQuarantined;
use Filagora\PluginsSecurity\Events\ScanFinished;
use Filagora\PluginsSecurity\Events\SeriousFindingFlagged;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Notifications\SecurityNotification;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Notification;

/**
 * The default emails for security events. Silent when `filagora-plugins-security.mail.enabled` is
 * off, for a host that sends its own from the same events.
 */
final class SendSecurityMail
{
    /**
     * Uploaders and owners get exactly one email per submission: this one, when the scan of the
     * upload ends (clean, flagged, quarantined or failed). Later scans stay on the dashboard.
     */
    public function scanFinished(ScanFinished $event): void
    {
        if (! $this->enabled() || ! $event->scan->triggered_by->emailsAuthorTheResult()) {
            return;
        }

        $release = $event->release;
        $scan = $event->scan;
        $severity = $scan->severity();
        $failed = $scan->status === ScanStatus::FAILED;

        $outcome = match (true) {
            $failed => __('filagora-plugins-security::notifications.scan_complete.outcome_failed'),
            $release->status === PluginStatus::QUARANTINED => __('filagora-plugins-security::notifications.scan_complete.outcome_quarantined', ['severity' => $severity->label()]),
            $severity !== ScanSeverity::NONE => __('filagora-plugins-security::notifications.scan_complete.outcome_flagged', [
                'count' => (int) array_sum($scan->finding_counts ?? []),
                'severity' => $severity->label(),
            ]),
            default => __('filagora-plugins-security::notifications.scan_complete.outcome_clear'),
        };

        $status = match (true) {
            $release->status === PluginStatus::QUARANTINED => __('filagora-plugins-security::notifications.scan_complete.status_held'),
            $release->status === PluginStatus::ACTIVE => __('filagora-plugins-security::notifications.scan_complete.status_live'),
            default => __('filagora-plugins-security::notifications.scan_complete.status_pending'),
        };

        $this->tellAuthors($release, new SecurityNotification('scan_complete', $release, $this->replace($release), [$outcome, $status]));
    }

    public function quarantined(ReleaseQuarantined $event): void
    {
        if (! $this->enabled() || ! $event->tellAuthors) {
            return;
        }

        $details = $event->scan instanceof SecurityScan
            ? [__('filagora-plugins-security::notifications.quarantined.reference', ['scan' => $event->scan->getKey(), 'version' => $event->scan->scanner_version])]
            : [];

        $this->tellAuthors($event->release, new SecurityNotification('quarantined', $event->release, $this->replace($event->release), $details));
    }

    public function cleared(QuarantineCleared $event): void
    {
        $uploader = Users::of($event->release->uploadedBy);

        if ($this->enabled() && $uploader !== null) {
            Notification::send($uploader, new SecurityNotification('quarantine_cleared', $event->release, $this->replace($event->release)));
        }
    }

    public function flagged(SeriousFindingFlagged $event): void
    {
        $support = config('filagora-plugins.mail.support_email');

        if (! $this->enabled() || ! is_string($support) || filter_var($support, FILTER_VALIDATE_EMAIL) === false) {
            return;
        }

        $release = $event->release;
        $counts = collect($event->scan->finding_counts ?? [])
            ->filter()
            ->map(static fn (int $count, string $severity): string => "{$severity}: {$count}")
            ->implode(', ');

        Notification::route('mail', $support)->notify(new SecurityNotification(
            'finding_flagged',
            $release,
            $this->replace($release) + ['severity' => $event->scan->severity()->label()],
            [
                __('filagora-plugins-security::notifications.finding_flagged.counts', ['counts' => $counts !== '' ? $counts : '-']),
                $release->status === PluginStatus::QUARANTINED
                    ? __('filagora-plugins-security::notifications.finding_flagged.held')
                    : __('filagora-plugins-security::notifications.finding_flagged.public'),
            ],
            forStaff: true,
        ));
    }

    /**
     * Only the person who asked for an AI review is told it is done; never the plugin's author.
     */
    public function reviewFinished(LlmReviewFinished $event): void
    {
        $requester = Users::of($event->scan->triggeredByUser);

        if (! $this->enabled() || $requester === null) {
            return;
        }

        $failed = $event->scan->status === ScanStatus::FAILED;
        $counts = collect($event->scan->finding_counts ?? [])
            ->filter()
            ->map(static fn (int $count, string $severity): string => "{$severity}: {$count}")
            ->implode(', ');

        Notification::send($requester, new SecurityNotification(
            $failed ? 'review_failed' : 'review_finished',
            $event->release,
            $this->replace($event->release) + ['severity' => $event->scan->severity()->label(), 'error' => (string) $event->scan->error],
            $failed ? [] : [__('filagora-plugins-security::notifications.review_finished.counts', ['counts' => $counts !== '' ? $counts : '-'])],
            forStaff: true,
        ));
    }

    private function tellAuthors(PluginRelease $release, SecurityNotification $notification): void
    {
        $people = collect([$release->uploadedBy, $release->plugin->owner])
            ->map(static fn (mixed $person): ?Authenticatable => $person instanceof Model ? Users::of($person) : null)
            ->filter()
            ->unique(static fn (Authenticatable $person): mixed => $person->getAuthIdentifier());

        if ($people->isNotEmpty()) {
            Notification::send($people, $notification);
        }
    }

    /**
     * @return array<string, scalar|null>
     */
    private function replace(PluginRelease $release): array
    {
        return ['plugin' => $release->plugin->name, 'version' => $release->displayVersion()];
    }

    private function enabled(): bool
    {
        return (bool) config('filagora-plugins-security.mail.enabled', true);
    }
}
