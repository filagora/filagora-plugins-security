<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Jobs;

use Carbon\CarbonImmutable;
use Filagora\Core\Support\UserModel;
use Filagora\Plugins\Support\Models;
use Filagora\PluginsSecurity\Analysis\ScanInterrupted;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\Scanner;
use Filagora\PluginsSecurity\Support\Config;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Scans one release out of band. One attempt: a failure records a failed scan, so the attempt is
 * visible to staff instead of disappearing.
 */
class ScanReleaseJob implements ShouldQueue
{
    use Queueable;

    public int $tries = 1;

    public int $timeout;

    public CarbonImmutable $queuedAt;

    public function __construct(
        public readonly int $releaseId,
        public readonly ScanTrigger $trigger = ScanTrigger::UPLOAD,
        public readonly int|string|null $triggeredById = null,
    ) {
        $this->onQueue(Config::queue());
        $this->timeout = (int) config('filagora-plugins-security.scanner.timeout_seconds', 600);
        $this->queuedAt = CarbonImmutable::now();
    }

    /**
     * @return list<object>
     */
    public function middleware(): array
    {
        return [
            (new WithoutOverlapping("filagora-plugins-security:scan-job:{$this->releaseId}"))
                ->dontRelease()
                ->expireAfter($this->timeout + 60),
        ];
    }

    public function handle(Scanner $scanner): void
    {
        $release = Models::class('release')::query()->find($this->releaseId);

        if ($release === null) {
            return;
        }

        $user = $this->triggeredById !== null ? UserModel::class()::query()->find($this->triggeredById) : null;

        try {
            $scanner->scan($release, $this->trigger, $user instanceof Authenticatable ? $user : null, $this->queuedAt);
        } catch (ScanInterrupted) {
            // The worker was told to stop. No scan was recorded; the sweep picks the release up.
            Log::info('A security scan was interrupted by a worker shutdown and will be redone by the sweep.', [
                'release_id' => $this->releaseId,
                'trigger' => $this->trigger->value,
            ]);
        }
    }

    public function failed(Throwable $exception): void
    {
        if ($exception instanceof ScanInterrupted) {
            return;
        }

        $release = Models::class('release')::query()->find($this->releaseId);

        if ($release === null) {
            return;
        }

        $scan = SecurityScan::query()->create([
            'plugin_release_id' => $release->getKey(),
            'kind' => ScanKind::STANDARD,
            'scanner_version' => Config::scannerVersion(),
            'status' => ScanStatus::FAILED,
            'triggered_by' => $this->trigger,
            'triggered_by_user_id' => $this->triggeredById,
            'queued_at' => $this->queuedAt,
            'started_at' => now(),
            'finished_at' => now(),
            'error' => mb_substr(mb_scrub(__('filagora-plugins-security::messages.job_failed', ['message' => $exception->getMessage()]), 'UTF-8'), 0, 2000),
        ]);

        $release->forceFill(['latest_security_scan_id' => $scan->getKey()])->saveQuietly();
    }
}
