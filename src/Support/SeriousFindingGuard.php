<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\Plugins\Contracts\ArchiveGuard;
use Filagora\Plugins\Models\Plugin;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\AcceptedFindings;

/**
 * Keeps a release active, out of the archive, while its latest scan still holds a finding at or
 * above `archive.keep_at_severity` that no moderator has accepted.
 */
final class SeriousFindingGuard implements ArchiveGuard
{
    public function __construct(private readonly AcceptedFindings $accepted) {}

    public function reasonToKeep(Plugin $plugin, PluginRelease $release): ?string
    {
        $threshold = ScanSeverity::tryFrom((string) config('filagora-plugins-security.archive.keep_at_severity'));

        if ($threshold === null || $threshold === ScanSeverity::NONE || $release->latest_security_scan_id === null) {
            return null;
        }

        $scan = SecurityScan::query()->find($release->latest_security_scan_id);

        if ($scan === null || $scan->kind !== ScanKind::STANDARD || $scan->status !== ScanStatus::COMPLETED) {
            return null;
        }

        return $this->accepted->effectiveSeverity($release, $scan)->isAtLeast($threshold)
            ? __('filagora-plugins-security::messages.guard.reason', ['severity' => $threshold->label()])
            : null;
    }
}
