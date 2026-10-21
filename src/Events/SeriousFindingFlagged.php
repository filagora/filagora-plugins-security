<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Events;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * The scan of a new upload found something serious (high or worse that nobody has accepted), so
 * staff should look. Dispatched for uploads only: a re-scan or the sweep would raise the same
 * alarm for the same finding over and over.
 */
final class SeriousFindingFlagged
{
    use Dispatchable;

    public function __construct(
        public readonly PluginRelease $release,
        public readonly SecurityScan $scan,
    ) {}
}
