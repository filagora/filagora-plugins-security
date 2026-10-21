<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Listeners;

use Filagora\Plugins\Events\ReleaseSubmitted;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Jobs\ScanReleaseJob;

/**
 * Queues a scan when a release is submitted, unless `scanner.dispatch_on_upload` is off.
 */
final class QueueScanOnSubmission
{
    public function handle(ReleaseSubmitted $event): void
    {
        if (config('filagora-plugins-security.scanner.dispatch_on_upload', true)) {
            ScanReleaseJob::dispatch((int) $event->release->getKey(), ScanTrigger::UPLOAD, $event->submittedBy->getAuthIdentifier());
        }
    }
}
