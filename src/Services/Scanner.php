<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Services;

use DateTimeInterface;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\Analyzers;
use Filagora\PluginsSecurity\Analysis\ArchiveExtractor;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Analysis\ScanInterrupted;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Events\ScanFinished;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Support\Config;
use Filagora\PluginsSecurity\Support\ReleaseArchives;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\Process\Exception\ProcessSignaledException;
use Throwable;

/**
 * Runs the registered analyzers over a stored release archive and records one scan. What the scan
 * means for the release (quarantine) is decided by `Quarantine` once the scan is saved.
 */
class Scanner
{
    /**
     * Caps on what is stored. Analyzer output comes from arbitrary uploaded source, so a hostile
     * release could otherwise produce a result too big to save.
     */
    private const MAX_PERSISTED_FINDINGS = 5000;

    private const MAX_STRING_LENGTH = 20000;

    /** SIGINT and SIGTERM: a worker shutting down, as opposed to a crash. Named here so ext-pcntl is not needed. */
    private const SHUTDOWN_SIGNALS = [2, 15];

    public function __construct(
        private readonly ArchiveExtractor $extractor,
        private readonly Analyzers $analyzers,
        private readonly Quarantine $quarantine,
        private readonly ReleaseArchives $archives,
    ) {}

    /**
     * @throws ScanInterrupted when the worker was told to stop part-way; nothing is recorded then
     */
    public function scan(
        PluginRelease $release,
        ScanTrigger $trigger,
        ?Authenticatable $triggeredBy = null,
        ?DateTimeInterface $queuedAt = null,
    ): SecurityScan {
        return Cache::lock("filagora-plugins-security:scan:{$release->getKey()}", 900)->block(
            30,
            fn (): SecurityScan => $this->run($release, $trigger, $triggeredBy, $queuedAt),
        );
    }

    private function run(PluginRelease $release, ScanTrigger $trigger, ?Authenticatable $triggeredBy, ?DateTimeInterface $queuedAt): SecurityScan
    {
        $scan = SecurityScan::query()->create([
            'plugin_release_id' => $release->getKey(),
            'kind' => ScanKind::STANDARD,
            'scanner_version' => Config::scannerVersion(),
            'status' => ScanStatus::RUNNING,
            'triggered_by' => $trigger,
            'triggered_by_user_id' => $triggeredBy?->getAuthIdentifier(),
            'queued_at' => $queuedAt,
            'started_at' => now(),
        ]);

        try {
            $archive = $this->archives->local($release);
        } catch (Throwable $e) {
            return $this->failed($release, $scan, $e->getMessage());
        }

        try {
            ['path' => $directory, 'cleanup' => $cleanup] = $this->extractor->extract($archive['path']);
        } catch (Throwable $e) {
            $archive['cleanup']();

            return $this->failed($release, $scan, $e->getMessage());
        }

        try {
            return $this->analyse($release, $scan, new ScanContext($release, $directory, $archive['path']));
        } finally {
            $cleanup();
            $archive['cleanup']();
        }
    }

    private function analyse(PluginRelease $release, SecurityScan $scan, ScanContext $context): SecurityScan
    {
        $findings = [];
        $versions = [];
        $anyCompleted = false;
        $anyFailed = false;

        foreach ($this->analyzers->all() as $analyzer) {
            $entry = ['version' => $analyzer->version()];

            if (! $analyzer->isAvailable()) {
                $versions[$analyzer->name()] = $entry + ['status' => 'skipped', 'note' => 'unavailable'];

                continue;
            }

            try {
                $result = $analyzer->analyze($context);
            } catch (ProcessSignaledException $e) {
                // A deploy or `queue:restart` signalled the worker and it reached the analyzer's
                // process. Not a failed scan: drop the row and let a later scan pick the release up.
                if (in_array($e->getSignal(), self::SHUTDOWN_SIGNALS, true)) {
                    $scan->delete();

                    throw new ScanInterrupted("The scan was interrupted by signal {$e->getSignal()}.", previous: $e);
                }

                report($e);
                $result = AnalyzerResult::failed($e->getMessage());
            } catch (Throwable $e) {
                report($e);
                $result = AnalyzerResult::failed($e->getMessage());
            }

            $entry['status'] = $result->status;

            if ($result->note !== null) {
                $entry['note'] = $result->note;
            }

            if ($result->isCompleted()) {
                $anyCompleted = true;

                foreach ($result->findings as $finding) {
                    $findings[] = $finding->toArray();
                }
            } elseif ($result->status === 'failed') {
                $anyFailed = true;
            }

            $versions[$analyzer->name()] = $entry;
        }

        $counts = [];

        foreach ($findings as $finding) {
            $counts[$finding['severity']] = ($counts[$finding['severity']] ?? 0) + 1;
        }

        $failed = $anyFailed && ! $anyCompleted;

        // Severity and counts come from the whole result; only the stored list is capped.
        $scan->update($this->scrub([
            'status' => $failed ? ScanStatus::FAILED : ScanStatus::COMPLETED,
            'highest_severity' => ScanSeverity::highest(array_column($findings, 'severity')),
            'finding_counts' => $counts,
            'findings' => $this->cap($findings),
            'analyzer_versions' => $versions,
            'error' => $failed ? 'Every analyzer failed.' : null,
            'finished_at' => now(),
        ]));

        return $this->finish($release, $scan);
    }

    private function failed(PluginRelease $release, SecurityScan $scan, string $message): SecurityScan
    {
        $scan->update($this->scrub([
            'status' => ScanStatus::FAILED,
            'error' => $message,
            'finished_at' => now(),
        ]));

        return $this->finish($release, $scan);
    }

    private function finish(PluginRelease $release, SecurityScan $scan): SecurityScan
    {
        // Quietly: moving the pointer must not run the release's saving hooks or its observers.
        $release->forceFill(['latest_security_scan_id' => $scan->getKey()])->saveQuietly();

        $scan->refresh();
        $this->quarantine->evaluateAfterScan($release, $scan);

        ScanFinished::dispatch($release->refresh(), $scan);

        return $scan;
    }

    /**
     * Valid UTF-8 and bounded length for every string stored. Analyzer text comes from arbitrary
     * bytes, and a mis-encoded file would otherwise make saving the JSON fail.
     *
     * @template TValue
     *
     * @param  TValue  $value
     * @return TValue
     */
    private function scrub(mixed $value): mixed
    {
        if (is_array($value)) {
            return array_map(fn (mixed $item): mixed => $this->scrub($item), $value);
        }

        if (! is_string($value)) {
            return $value;
        }

        $clean = mb_scrub($value, 'UTF-8');

        return mb_strlen($clean, 'UTF-8') > self::MAX_STRING_LENGTH
            ? mb_substr($clean, 0, self::MAX_STRING_LENGTH, 'UTF-8').'… [truncated]'
            : $clean;
    }

    /**
     * @param  list<array<string, mixed>>  $findings
     * @return list<array<string, mixed>>
     */
    private function cap(array $findings): array
    {
        if (count($findings) <= self::MAX_PERSISTED_FINDINGS) {
            return $findings;
        }

        $kept = array_slice($findings, 0, self::MAX_PERSISTED_FINDINGS - 1);
        $kept[] = [
            'analyzer' => 'scanner',
            'rule_id' => 'findings-truncated',
            'severity' => ScanSeverity::INFO->value,
            'title' => __('filagora-plugins-security::messages.truncated', [
                'omitted' => count($findings) - (self::MAX_PERSISTED_FINDINGS - 1),
                'limit' => self::MAX_PERSISTED_FINDINGS,
            ]),
            'file' => null,
            'line' => null,
            'snippet' => null,
            'fingerprint' => 'findings-truncated',
        ];

        return $kept;
    }
}
