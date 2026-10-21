<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Support;

use Closure;
use Filagora\PluginsSecurity\Contracts\LlmReviewer;

/**
 * A language model the test speaks for: it answers with what the closure returns (or throws), and
 * remembers each request.
 */
final class FakeReviewer implements LlmReviewer
{
    /** @var list<list<array{role: string, content: string}>> */
    public array $requests = [];

    /**
     * @param  Closure(list<array{role: string, content: string}>, int): string  $answer
     */
    public function __construct(private readonly Closure $answer, private readonly bool $configured = true) {}

    public static function answering(string $answer): self
    {
        return new self(fn () => $answer);
    }

    public function isConfigured(): bool
    {
        return $this->configured;
    }

    public function model(): string
    {
        return 'test-model';
    }

    public function complete(array $messages): string
    {
        $this->requests[] = $messages;

        return ($this->answer)($messages, count($this->requests));
    }
}
