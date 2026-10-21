<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Jobs;

use Carbon\CarbonImmutable;
use Filagora\Core\Support\UserModel;
use Filagora\Plugins\Support\Models;
use Filagora\PluginsSecurity\Services\LlmReviews;
use Filagora\PluginsSecurity\Support\Config;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Throwable;

/**
 * Runs a moderator's AI review of one release out of band. One attempt: a failure is recorded as a
 * failed review, so staff see it.
 */
class LlmReviewJob implements ShouldQueue
{
    use Queueable;

    public int $tries = 1;

    public int $timeout;

    public CarbonImmutable $queuedAt;

    public function __construct(
        public readonly int $releaseId,
        public readonly int|string|null $requestedById = null,
    ) {
        $this->onQueue(Config::queue());

        $llm = (array) config('filagora-plugins-security.analyzers.llm');
        $this->timeout = ((int) ($llm['timeout_seconds'] ?? 600) * max(1, (int) ($llm['max_batches'] ?? 6))) + 120;
        $this->queuedAt = CarbonImmutable::now();
    }

    /**
     * @return list<object>
     */
    public function middleware(): array
    {
        return [
            (new WithoutOverlapping("filagora-plugins-security:review-job:{$this->releaseId}"))
                ->dontRelease()
                ->expireAfter($this->timeout + 60),
        ];
    }

    public function handle(LlmReviews $reviews): void
    {
        $release = Models::class('release')::query()->find($this->releaseId);

        if ($release === null) {
            return;
        }

        $reviews->review($release, $this->requester(), $this->queuedAt);
    }

    public function failed(Throwable $exception): void
    {
        $release = Models::class('release')::query()->find($this->releaseId);

        if ($release === null) {
            return;
        }

        app(LlmReviews::class)->recordFailure(
            $release,
            $this->requester(),
            $this->queuedAt,
            mb_substr(mb_scrub(__('filagora-plugins-security::messages.llm.job_failed', ['message' => $exception->getMessage()]), 'UTF-8'), 0, 2000),
        );
    }

    private function requester(): ?Authenticatable
    {
        if ($this->requestedById === null) {
            return null;
        }

        $user = UserModel::class()::query()->find($this->requestedById);

        return $user instanceof Authenticatable ? $user : null;
    }
}
