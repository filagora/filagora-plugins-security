<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Support\Models;
use Illuminate\Database\Eloquent\Builder;

/**
 * Releases a scan is due for: never scanned, or last scanned by an older scanner version.
 */
final class StaleReleases
{
    /**
     * @return Builder<PluginRelease>
     */
    public static function query(bool $activeOnly = true): Builder
    {
        $version = Config::scannerVersion();

        return Models::class('release')::query()
            ->when($activeOnly, fn (Builder $query) => $query->where('status', PluginStatus::ACTIVE->value))
            ->where(function (Builder $query) use ($version): void {
                $query->whereNull('latest_security_scan_id')
                    ->orWhereHas('latestSecurityScan', fn (Builder $scan) => $scan->where('scanner_version', '<', $version));
            })
            ->orderBy('id');
    }
}
