<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis\Analyzers;

use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Analysis\ScanFinding;
use Filagora\PluginsSecurity\Contracts\ReleaseAnalyzer;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Illuminate\Support\Facades\Process;

/**
 * Runs Semgrep against the extracted archive with the package's rules, or the ones configured in
 * `ruleset_path`. Off by default; switch it on once the binary is installed.
 */
class SemgrepAnalyzer implements ReleaseAnalyzer
{
    /** Bump when the invocation or severity mapping changes. */
    public const VERSION = 1;

    private ?string $resolvedVersion = null;

    private ?bool $binaryOk = null;

    public function name(): string
    {
        return 'semgrep';
    }

    public function version(): string
    {
        if ($this->resolvedVersion !== null) {
            return $this->resolvedVersion;
        }

        $binaryVersion = trim(Process::timeout(15)->run([$this->binary(), '--version'])->output());
        $binaryVersion = $binaryVersion !== '' ? $binaryVersion : (string) self::VERSION;

        return $this->resolvedVersion = $binaryVersion.'/rules-'.substr($this->rulesetHash(), 0, 12);
    }

    public function isAvailable(): bool
    {
        if (! (bool) config('filagora-plugins-security.analyzers.semgrep.enabled', false)) {
            return false;
        }

        if (! is_dir($this->rulesetPath()) && ! is_file($this->rulesetPath())) {
            return false;
        }

        if ($this->binaryOk !== null) {
            return $this->binaryOk;
        }

        return $this->binaryOk = Process::timeout(15)->run([$this->binary(), '--version'])->successful();
    }

    public function analyze(ScanContext $context): AnalyzerResult
    {
        $timeout = (int) config('filagora-plugins-security.analyzers.semgrep.timeout_seconds', 300);

        $result = Process::timeout($timeout)->run([
            $this->binary(),
            'scan',
            '--config', $this->rulesetPath(),
            '--json',
            '--quiet',
            '--metrics=off',
            '--disable-version-check',
            '--timeout', '30',
            $context->extractedPath,
        ]);

        // semgrep: 0 = no findings, 1 = findings, >=2 = fatal error.
        if ($result->exitCode() >= 2) {
            return AnalyzerResult::failed('semgrep error: '.trim($result->errorOutput() ?: $result->output()));
        }

        $decoded = json_decode($result->output(), true);
        if (! is_array($decoded) || ! isset($decoded['results']) || ! is_array($decoded['results'])) {
            return AnalyzerResult::failed('semgrep produced no parseable JSON.');
        }

        $findings = [];
        foreach ($decoded['results'] as $match) {
            if (! is_array($match)) {
                continue;
            }

            $ruleId = (string) ($match['check_id'] ?? 'semgrep-finding');
            $extra = is_array($match['extra'] ?? null) ? $match['extra'] : [];
            $start = is_array($match['start'] ?? null) ? $match['start'] : [];
            $dotPos = strrpos($ruleId, '.');

            $findings[] = new ScanFinding(
                $this->name(),
                'semgrep-'.substr($ruleId, $dotPos !== false ? $dotPos + 1 : 0),
                $this->mapSeverity((string) ($extra['severity'] ?? 'WARNING')),
                trim((string) ($extra['message'] ?? $ruleId)),
                $this->relativePath($context, (string) ($match['path'] ?? '')),
                isset($start['line']) ? (int) $start['line'] : null,
            );
        }

        return AnalyzerResult::completed($findings);
    }

    private function mapSeverity(string $semgrepSeverity): ScanSeverity
    {
        return match (strtoupper($semgrepSeverity)) {
            'ERROR', 'HIGH', 'CRITICAL' => ScanSeverity::HIGH,
            'WARNING', 'MEDIUM' => ScanSeverity::MEDIUM,
            default => ScanSeverity::LOW,
        };
    }

    private function binary(): string
    {
        return (string) config('filagora-plugins-security.analyzers.semgrep.binary', 'semgrep');
    }

    private function rulesetPath(): string
    {
        $path = config('filagora-plugins-security.analyzers.semgrep.ruleset_path');

        return is_string($path) && $path !== '' ? $path : __DIR__.'/../../../resources/semgrep';
    }

    private function rulesetHash(): string
    {
        $path = $this->rulesetPath();
        if (is_file($path)) {
            return hash_file('sha256', $path) ?: '';
        }

        if (! is_dir($path)) {
            return '';
        }

        $parts = [];
        foreach (glob(rtrim($path, '/').'/*.{yml,yaml}', GLOB_BRACE) ?: [] as $file) {
            $parts[] = basename($file).':'.(hash_file('sha256', $file) ?: '');
        }
        sort($parts);

        return hash('sha256', implode('|', $parts));
    }

    private function relativePath(ScanContext $context, string $absolute): ?string
    {
        if ($absolute === '') {
            return null;
        }

        if (str_starts_with($absolute, $context->extractedPath)) {
            return ltrim(substr($absolute, strlen($context->extractedPath)), '/') ?: null;
        }

        return $absolute;
    }
}
