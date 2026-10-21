<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Console;

use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Jobs\ScanReleaseJob;
use Filagora\PluginsSecurity\Support\StaleReleases;
use Illuminate\Console\Command;

/**
 * Queues scans for a small batch of active releases left stale by a scanner-version bump, so a bump
 * does not drop dozens of minutes-long scans at once. Schedule it, every half an hour for example.
 */
class SecuritySweepCommand extends Command
{
    protected $signature = 'filagora:plugins:security-sweep
        {--limit= : Releases to queue this run (default: sweep.batch_size)}
        {--dry-run : List what would be queued and exit}';

    protected $description = 'Queue security scans for active releases whose latest scan is missing or from an older scanner version.';

    public function handle(): int
    {
        if (! config('filagora-plugins-security.sweep.enabled', true)) {
            $this->info('The sweep is switched off.');

            return self::SUCCESS;
        }

        $limit = max(1, (int) ($this->option('limit') ?: config('filagora-plugins-security.sweep.batch_size', 4)));
        $ids = StaleReleases::query()->limit($limit)->pluck('id');

        if ($ids->isEmpty()) {
            $this->info('No releases are due for a scan.');

            return self::SUCCESS;
        }

        foreach ($ids as $id) {
            if (! $this->option('dry-run')) {
                ScanReleaseJob::dispatch((int) $id, ScanTrigger::SWEEP);
            }

            $this->line(($this->option('dry-run') ? 'Would queue' : 'Queued')." release #{$id}");
        }

        return self::SUCCESS;
    }
}
