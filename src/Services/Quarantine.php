<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Services;

use Filagora\Core\Contracts\AccessChecker;
use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Support\Models;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\SecurityRefusal;
use Filagora\PluginsSecurity\Events\QuarantineCleared;
use Filagora\PluginsSecurity\Events\ReleaseQuarantined;
use Filagora\PluginsSecurity\Events\SeriousFindingFlagged;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Support\Config;
use Filagora\PluginsSecurity\Support\Gates;
use Filagora\PluginsSecurity\Support\Names;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Applies and lifts the quarantine on a release.
 *
 * A quarantine sets the release to `PluginStatus::QUARANTINED`, which every listing, search,
 * download and feed already treats as not public, and remembers the status it had so a clear
 * restores it exactly. Either way a staff note records why.
 */
class Quarantine
{
    public function __construct(
        private readonly AccessChecker $access,
        private readonly AcceptedFindings $accepted,
    ) {}

    /**
     * Decide what a finished scan means for the release: quarantine on a finding at or above the
     * threshold, tell staff of anything serious in a new upload, and lift a quarantine that a clean
     * re-scan no longer supports (when `auto_clear_when_clean` is on).
     */
    public function evaluateAfterScan(PluginRelease $release, SecurityScan $scan): void
    {
        if ($scan->status !== ScanStatus::COMPLETED) {
            return;
        }

        // Findings a moderator has accepted for this plugin do not count, so a known false
        // positive does not quarantine the release again on every re-scan.
        $severity = $this->accepted->effectiveSeverity($release, $scan);

        if ($severity !== ScanSeverity::NONE && $severity->isAtLeast(Config::quarantineThreshold())) {
            if (! $release->isQuarantined() && $this->canBeQuarantined($release)) {
                $this->quarantineAutomatically($release, $scan);
            }

            if ($scan->triggered_by->emailsSupportTheFinding()) {
                SeriousFindingFlagged::dispatch($release->refresh(), $scan);
            }

            return;
        }

        if ($severity->isAtLeast(ScanSeverity::HIGH) && $scan->triggered_by->emailsSupportTheFinding()) {
            SeriousFindingFlagged::dispatch($release, $scan);
        }

        if ($severity === ScanSeverity::NONE
            && $release->isQuarantined()
            && config('filagora-plugins-security.scanner.auto_clear_when_clean')
        ) {
            $this->lift($release, null, __('filagora-plugins-security::messages.notes.auto_cleared', ['version' => $scan->scanner_version]));
        }
    }

    /**
     * Quarantine a release by hand, on the latest scan if there is one.
     *
     * @throws SecurityRefused
     */
    public function quarantine(PluginRelease $release, Authenticatable $moderator, string $note): void
    {
        $this->assertAllowed($moderator);

        if (trim($note) === '') {
            throw new SecurityRefused(SecurityRefusal::NOTE_REQUIRED);
        }

        if ($release->isQuarantined()) {
            throw new SecurityRefused(SecurityRefusal::ALREADY_QUARANTINED);
        }

        if (! $this->canBeQuarantined($release)) {
            throw new SecurityRefused(SecurityRefusal::NOT_QUARANTINABLE);
        }

        $scan = $release->latest_security_scan_id !== null ? SecurityScan::query()->find($release->latest_security_scan_id) : null;

        $this->apply($release, $scan, __('filagora-plugins-security::messages.notes.quarantined_by', ['name' => Names::of($moderator), 'note' => trim($note)]), $moderator->getAuthIdentifier());

        ReleaseQuarantined::dispatch($release->refresh(), $scan, $moderator, true);
    }

    /**
     * Lift a quarantine by hand.
     *
     * @throws SecurityRefused
     */
    public function clear(PluginRelease $release, Authenticatable $moderator, string $note): void
    {
        $this->assertAllowed($moderator);

        if (trim($note) === '') {
            throw new SecurityRefused(SecurityRefusal::NOTE_REQUIRED);
        }

        if (! $release->isQuarantined()) {
            throw new SecurityRefused(SecurityRefusal::NOT_QUARANTINED);
        }

        $this->lift($release, $moderator, __('filagora-plugins-security::messages.notes.cleared_by', ['name' => Names::of($moderator), 'note' => trim($note)]));
    }

    private function quarantineAutomatically(PluginRelease $release, SecurityScan $scan): void
    {
        $this->apply($release, $scan, __('filagora-plugins-security::messages.notes.auto_quarantined', ['scan' => $scan->getKey(), 'severity' => $scan->severity()->label()]), null);

        ReleaseQuarantined::dispatch($release->refresh(), $scan, null, $scan->triggered_by->emailsAuthorTheQuarantine());
    }

    private function canBeQuarantined(PluginRelease $release): bool
    {
        return in_array($release->status, [PluginStatus::ACTIVE, PluginStatus::MODERATED], true);
    }

    private function apply(PluginRelease $release, ?SecurityScan $scan, string $note, int|string|null $moderatorId): void
    {
        $release->forceFill([
            'status_before_quarantine' => $release->status->value,
            'status' => PluginStatus::QUARANTINED,
            'quarantined_at' => now(),
            'quarantine_scan_id' => $scan?->getKey(),
            'quarantine_cleared_at' => null,
            'quarantine_cleared_by_id' => null,
            'quarantine_note' => null,
        ])->save();

        $this->note($release, $moderatorId, $note);
    }

    private function lift(PluginRelease $release, ?Authenticatable $moderator, string $note): void
    {
        $restore = PluginStatus::tryFrom((string) $release->status_before_quarantine) ?? PluginStatus::MODERATED;

        $release->forceFill([
            'status' => $restore,
            'status_before_quarantine' => null,
            'quarantined_at' => null,
            'quarantine_cleared_at' => now(),
            'quarantine_cleared_by_id' => $moderator?->getAuthIdentifier(),
            'quarantine_note' => $note,
        ])->save();

        $this->note($release, $moderator?->getAuthIdentifier(), $note);

        QuarantineCleared::dispatch($release->refresh(), $moderator);
    }

    private function note(PluginRelease $release, int|string|null $moderatorId, string $note): void
    {
        Models::class('moderator_note')::query()->create([
            'plugin_id' => $release->plugin_id,
            'moderator_id' => $moderatorId,
            'note' => '['.__('filagora-plugins-security::messages.notes.release', ['version' => $release->version]).'] '.$note,
        ]);
    }

    /**
     * @throws SecurityRefused
     */
    private function assertAllowed(Authenticatable $moderator): void
    {
        if (! $this->access->allows($moderator, Gates::key(Gates::SECURITY))) {
            throw new SecurityRefused(SecurityRefusal::NOT_PERMITTED);
        }
    }
}
