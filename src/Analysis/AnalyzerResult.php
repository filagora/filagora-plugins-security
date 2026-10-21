<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis;

/**
 * What one analyzer made of an archive.
 */
final readonly class AnalyzerResult
{
    /**
     * @param  'completed'|'skipped'|'failed'  $status
     * @param  list<ScanFinding>  $findings
     */
    private function __construct(
        public string $status,
        public array $findings,
        public ?string $note = null,
    ) {}

    /**
     * @param  list<ScanFinding>  $findings
     */
    public static function completed(array $findings): self
    {
        return new self('completed', $findings);
    }

    public static function skipped(string $reason): self
    {
        return new self('skipped', [], $reason);
    }

    public static function failed(string $error): self
    {
        return new self('failed', [], $error);
    }

    public function isCompleted(): bool
    {
        return $this->status === 'completed';
    }
}
