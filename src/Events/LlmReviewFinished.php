<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Events;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * An AI review ended, completed or failed. The person who asked for it is
 * `$scan->triggeredByUser`; the plugin's author is never told.
 */
final class LlmReviewFinished
{
    use Dispatchable;

    public function __construct(
        public readonly PluginRelease $release,
        public readonly SecurityScan $scan,
    ) {}
}
