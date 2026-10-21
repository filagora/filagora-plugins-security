<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\PluginsSecurity\Enums\ScanSeverity;

/**
 * The scanner settings that more than one class reads.
 */
final class Config
{
    public static function scannerVersion(): int
    {
        return (int) config('filagora-plugins-security.scanner.version', 1);
    }

    public static function queue(): ?string
    {
        $queue = config('filagora-plugins-security.scanner.queue');

        return is_string($queue) && $queue !== '' ? $queue : null;
    }

    public static function quarantineThreshold(): ScanSeverity
    {
        $threshold = ScanSeverity::tryFrom((string) config('filagora-plugins-security.scanner.quarantine_threshold', 'critical'));

        // "none" would quarantine everything that was scanned; treat it as unset.
        return $threshold === null || $threshold === ScanSeverity::NONE ? ScanSeverity::CRITICAL : $threshold;
    }
}
