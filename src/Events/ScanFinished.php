<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Events;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A standard scan ended, completed or failed, and any quarantine it called for has been applied.
 * The release is as it stands after that.
 */
final class ScanFinished
{
    use Dispatchable;

    public function __construct(
        public readonly PluginRelease $release,
        public readonly SecurityScan $scan,
    ) {}
}
