<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis;

use Filagora\PluginsSecurity\Enums\ScanSeverity;

/**
 * One issue an analyzer found. The fingerprint is the same on every scan of the same code, so a
 * moderator's decision about a finding carries to later scans.
 */
final readonly class ScanFinding
{
    public function __construct(
        public string $analyzer,
        public string $ruleId,
        public ScanSeverity $severity,
        public string $title,
        public ?string $file = null,
        public ?int $line = null,
        public ?string $snippet = null,
        public ?string $explanation = null,
        public ?string $confidence = null,
        public ?string $suggestion = null,
    ) {}

    public function fingerprint(): string
    {
        return substr(hash('sha256', implode("\0", [
            $this->analyzer,
            $this->ruleId,
            $this->file ?? '',
            $this->normalizedSnippet(),
        ])), 0, 32);
    }

    /**
     * The explanation, confidence and suggestion are there only for findings that carry them (the
     * language-model review), so the others are stored without empty keys.
     *
     * @return array{analyzer: string, rule_id: string, severity: string, title: string, file: ?string, line: ?int, snippet: ?string, fingerprint: string, explanation?: string, confidence?: string, suggestion?: string}
     */
    public function toArray(): array
    {
        return [
            'analyzer' => $this->analyzer,
            'rule_id' => $this->ruleId,
            'severity' => $this->severity->value,
            'title' => $this->title,
            'file' => $this->file,
            'line' => $this->line,
            'snippet' => $this->snippet,
            'fingerprint' => $this->fingerprint(),
        ] + array_filter([
            'explanation' => $this->explanation,
            'confidence' => $this->confidence,
            'suggestion' => $this->suggestion,
        ], static fn (?string $value): bool => $value !== null);
    }

    private function normalizedSnippet(): string
    {
        return trim(preg_replace('/\s+/', ' ', (string) $this->snippet) ?? '');
    }
}
