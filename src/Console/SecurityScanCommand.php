<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Console;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Support\Models;
use Filagora\PluginsSecurity\Analysis\ScanInterrupted;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Jobs\ScanReleaseJob;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\Scanner;
use Filagora\PluginsSecurity\Support\StaleReleases;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

class SecurityScanCommand extends Command
{
    protected $signature = 'filagora:plugins:security-scan
        {--release=* : Release ids to scan}
        {--plugin=* : Plugin slugs or ids whose releases to scan}
        {--all : Every release, ignoring the default active-only filter}
        {--status=active : Only releases with this status ("any" for no filter)}
        {--never-scanned : Only releases that have never been scanned}
        {--stale : Only releases never scanned or last scanned by an older scanner version}
        {--trigger=rescan : upload|manual|backfill|sweep|rescan}
        {--sync : Scan each release here instead of queueing a job}
        {--limit= : Stop after this many releases}
        {--sleep-ms=0 : Pause between releases}
        {--prune : Instead of scanning, delete redundant scan history: keeps the latest scan per scanner version, the latest and the one behind a quarantine}
        {--dry-run : List what would be scanned or pruned and exit}';

    protected $description = 'Scan plugin releases for security problems, or prune old scans.';

    public function handle(Scanner $scanner): int
    {
        if ($this->option('prune')) {
            return $this->prune();
        }

        $trigger = ScanTrigger::tryFrom((string) $this->option('trigger'));

        if (! $trigger instanceof ScanTrigger) {
            $this->error('Invalid --trigger. Use one of: upload, manual, backfill, sweep, rescan.');

            return self::FAILURE;
        }

        $releases = $this->query()->get();

        if ($releases->isEmpty()) {
            $this->info('No matching releases.');

            return self::SUCCESS;
        }

        $sync = (bool) $this->option('sync');
        $dryRun = (bool) $this->option('dry-run');

        $this->info(sprintf('%s %d release(s).', $dryRun ? 'Would scan' : ($sync ? 'Scanning' : 'Queueing scans for'), $releases->count()));

        foreach ($releases as $release) {
            $label = sprintf('#%d %s %s', $release->getKey(), $release->plugin->slug ?? '?', $release->version);

            if ($dryRun) {
                $this->line("  - {$label}");

                continue;
            }

            if ($sync) {
                try {
                    $scan = $scanner->scan($release, $trigger);
                } catch (ScanInterrupted) {
                    $this->warn('  - interrupted by a shutdown signal; stopping. The rest stay due for the next run.');

                    return self::SUCCESS;
                }

                $this->line(sprintf('  - %s: %s / %s', $label, $scan->status->value, $scan->severity()->value));
            } else {
                ScanReleaseJob::dispatch((int) $release->getKey(), $trigger);
                $this->line("  - {$label} queued");
            }

            if (($sleep = max(0, (int) $this->option('sleep-ms'))) > 0) {
                usleep($sleep * 1000);
            }
        }

        return self::SUCCESS;
    }

    /**
     * @return Builder<PluginRelease>
     */
    private function query(): Builder
    {
        $query = $this->option('stale')
            ? StaleReleases::query(activeOnly: false)
            : Models::class('release')::query()->orderBy('id');

        $query->with('plugin:id,slug');

        /** @var list<string> $releaseIds */
        $releaseIds = (array) $this->option('release');

        if ($releaseIds !== []) {
            $query->whereIn('id', array_map('intval', $releaseIds));
        }

        /** @var list<string> $plugins */
        $plugins = (array) $this->option('plugin');

        if ($plugins !== []) {
            $query->whereHas('plugin', function (Builder $plugin) use ($plugins): void {
                $plugin->whereIn('slug', $plugins)
                    ->orWhereIn('id', array_map('intval', array_filter($plugins, 'is_numeric')));
            });
        }

        $status = (string) $this->option('status');

        if (! $this->option('all') && $status !== 'any' && $status !== '') {
            $query->where('status', $status);
        }

        if ($this->option('never-scanned')) {
            $query->whereNull('latest_security_scan_id');
        }

        if (($limit = (int) $this->option('limit')) > 0) {
            $query->limit($limit);
        }

        return $query;
    }

    private function prune(): int
    {
        $limit = max(0, (int) $this->option('limit'));
        $deletable = [];

        foreach (Models::class('release')::query()->whereHas('securityScans')->lazyById(200) as $release) {
            $protected = array_values(array_filter([(int) $release->latest_security_scan_id, (int) $release->quarantine_scan_id]));
            $seen = [];

            $scans = SecurityScan::query()
                ->where('plugin_release_id', $release->getKey())
                ->where('kind', ScanKind::STANDARD->value)
                ->orderByDesc('id')
                ->get(['id', 'scanner_version']);

            foreach ($scans as $scan) {
                // A protected scan is always kept, and covers its own version too.
                if (in_array((int) $scan->getKey(), $protected, true) || ! isset($seen[$scan->scanner_version])) {
                    $seen[$scan->scanner_version] = true;

                    continue;
                }

                $deletable[] = (int) $scan->getKey();
            }

            if ($limit > 0 && count($deletable) >= $limit) {
                break;
            }
        }

        if ($limit > 0) {
            $deletable = array_slice($deletable, 0, $limit);
        }

        if ($deletable === []) {
            $this->info('Nothing to prune.');

            return self::SUCCESS;
        }

        if ($this->option('dry-run')) {
            $this->info('Would delete '.count($deletable).' redundant scan(s).');

            return self::SUCCESS;
        }

        $this->info('Pruned '.SecurityScan::query()->whereIn('id', $deletable)->delete().' redundant scan(s).');

        return self::SUCCESS;
    }
}
