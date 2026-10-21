<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Services;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Models\FindingReview;
use Filagora\PluginsSecurity\Models\SecurityScan;

/**
 * Which findings a moderator has accepted for a plugin, and what a scan comes to without them.
 */
class AcceptedFindings
{
    /**
     * The fingerprints accepted for the release's plugin.
     *
     * @return list<string>
     */
    public function for(PluginRelease $release): array
    {
        return FindingReview::query()->where('plugin_id', $release->plugin_id)->pluck('fingerprint')->all();
    }

    /**
     * The worst severity among the scan's findings that nobody has accepted for the release's
     * plugin. A scan with no per-finding detail counts as what it recorded.
     */
    public function effectiveSeverity(PluginRelease $release, SecurityScan $scan): ScanSeverity
    {
        $findings = $scan->findings ?? [];

        if ($findings === []) {
            return $scan->severity();
        }

        $accepted = array_flip($this->for($release));
        $severities = [];

        foreach ($findings as $finding) {
            $fingerprint = (string) ($finding['fingerprint'] ?? '');

            if ($fingerprint === '' || ! isset($accepted[$fingerprint])) {
                $severities[] = (string) ($finding['severity'] ?? '');
            }
        }

        return ScanSeverity::highest($severities);
    }
}
