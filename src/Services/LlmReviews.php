<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Services;

use DateTimeInterface;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Analysis\Analyzers\LlmAnalyzer;
use Filagora\PluginsSecurity\Analysis\ArchiveExtractor;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Analysis\ScanFinding;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Events\LlmReviewFinished;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Support\ReleaseArchives;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Throwable;

/**
 * Runs an AI review at a moderator's request and stores it as a scan of kind `llm`. Deliberately
 * apart from `Scanner`: a review never becomes the release's latest scan, never decides a
 * quarantine, and never tells the author.
 */
class LlmReviews
{
    private const MAX_STRING_LENGTH = 20000;

    public function __construct(
        private readonly ArchiveExtractor $extractor,
        private readonly ReleaseArchives $archives,
        private readonly LlmAnalyzer $analyzer,
    ) {}

    public function isAvailable(): bool
    {
        return $this->analyzer->isAvailable();
    }

    public function review(PluginRelease $release, ?Authenticatable $requestedBy = null, ?DateTimeInterface $queuedAt = null): SecurityScan
    {
        $scan = Cache::lock("filagora-plugins-security:review:{$release->getKey()}", 900)->block(
            30,
            fn (): SecurityScan => $this->run($release, $requestedBy, $queuedAt),
        );

        LlmReviewFinished::dispatch($release, $scan);

        return $scan;
    }

    /**
     * Record a review that failed outside the review itself, such as a job that ran out of time.
     */
    public function recordFailure(PluginRelease $release, ?Authenticatable $requestedBy, ?DateTimeInterface $queuedAt, string $message): SecurityScan
    {
        $scan = $this->start($release, $requestedBy, $queuedAt);
        $this->fail($scan, $message);

        LlmReviewFinished::dispatch($release, $scan);

        return $scan;
    }

    private function start(PluginRelease $release, ?Authenticatable $requestedBy, ?DateTimeInterface $queuedAt): SecurityScan
    {
        return SecurityScan::query()->create([
            'plugin_release_id' => $release->getKey(),
            'kind' => ScanKind::LLM,
            'scanner_version' => LlmAnalyzer::VERSION,
            'status' => ScanStatus::RUNNING,
            'triggered_by' => ScanTrigger::MANUAL,
            'triggered_by_user_id' => $requestedBy?->getAuthIdentifier(),
            'queued_at' => $queuedAt,
            'started_at' => now(),
        ]);
    }

    private function run(PluginRelease $release, ?Authenticatable $requestedBy, ?DateTimeInterface $queuedAt): SecurityScan
    {
        $scan = $this->start($release, $requestedBy, $queuedAt);

        if (! $this->analyzer->isAvailable()) {
            return $this->fail($scan, __('filagora-plugins-security::messages.llm.not_configured'));
        }

        try {
            $archive = $this->archives->local($release);
        } catch (Throwable $e) {
            return $this->fail($scan, $e->getMessage());
        }

        try {
            ['path' => $directory, 'cleanup' => $cleanup] = $this->extractor->extract($archive['path']);
        } catch (Throwable $e) {
            $archive['cleanup']();

            return $this->fail($scan, $e->getMessage());
        }

        try {
            $result = $this->analyzer->analyze(new ScanContext($release, $directory, $archive['path']));
        } catch (Throwable $e) {
            report($e);

            return $this->fail($scan, $e->getMessage());
        } finally {
            $cleanup();
            $archive['cleanup']();
        }

        if (! $result->isCompleted()) {
            return $this->fail($scan, (string) $result->note);
        }

        $findings = array_map(static fn (ScanFinding $finding): array => $finding->toArray(), $result->findings);
        $counts = [];

        foreach ($findings as $finding) {
            $counts[$finding['severity']] = ($counts[$finding['severity']] ?? 0) + 1;
        }

        $scan->update($this->scrub([
            'status' => ScanStatus::COMPLETED,
            'highest_severity' => ScanSeverity::highest(array_column($findings, 'severity')),
            'finding_counts' => $counts,
            'findings' => $findings,
            'analyzer_versions' => ['llm' => ['version' => $this->analyzer->version(), 'status' => 'completed']],
            'error' => null,
            'finished_at' => now(),
        ]));

        return $scan;
    }

    private function fail(SecurityScan $scan, string $message): SecurityScan
    {
        $scan->update($this->scrub([
            'status' => ScanStatus::FAILED,
            'error' => $message !== '' ? $message : __('filagora-plugins-security::messages.llm.failed'),
            'analyzer_versions' => ['llm' => ['version' => $this->analyzer->version(), 'status' => 'failed']],
            'finished_at' => now(),
        ]));

        return $scan;
    }

    /**
     * Model output and exception text can be any bytes: make every string valid UTF-8 and bounded
     * before it reaches a JSON column.
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
}
