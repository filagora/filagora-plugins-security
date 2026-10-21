<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis\Analyzers;

use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Analysis\ScanFinding;
use Filagora\PluginsSecurity\Contracts\ReleaseAnalyzer;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Str;

/**
 * Scans the extracted archive with ClamAV — `clamdscan` (talks to a running
 * clamd, fast) when available, otherwise `clamscan` (standalone, loads the
 * whole signature DB per run). Any signature hit is CRITICAL. Unavailable
 * (disabled, or no ClamAV binary) => the scan records it as skipped rather
 * than failing.
 */
class ClamavAnalyzer implements ReleaseAnalyzer
{
    /** Bump when the invocation or parsing changes. */
    public const VERSION = 1;

    private ?string $resolvedVersion = null;

    private ?bool $binaryOk = null;

    private ?string $resolvedBinary = null;

    public function name(): string
    {
        return 'clamav';
    }

    public function version(): string
    {
        if ($this->resolvedVersion !== null) {
            return $this->resolvedVersion;
        }

        $binary = $this->binary();
        if ($binary === null) {
            return $this->resolvedVersion = (string) self::VERSION;
        }

        $line = trim(Process::timeout(10)->run([$binary, '--version'])->output());

        // "ClamAV 1.4.2/27142/Wed ..." -> "1.4.2/27142"
        if (preg_match('#ClamAV\s+([0-9.]+)(?:/(\d+))?#i', $line, $m) === 1) {
            return $this->resolvedVersion = $m[1].(isset($m[2]) ? '/'.$m[2] : '');
        }

        return $this->resolvedVersion = (string) self::VERSION;
    }

    public function isAvailable(): bool
    {
        if (! (bool) config('filagora-plugins-security.analyzers.clamav.enabled', false)) {
            return false;
        }

        if ($this->binaryOk !== null) {
            return $this->binaryOk;
        }

        return $this->binaryOk = $this->binary() !== null;
    }

    public function analyze(ScanContext $context): AnalyzerResult
    {
        $binary = $this->binary();
        if ($binary === null) {
            return AnalyzerResult::skipped('no ClamAV binary found');
        }

        $timeout = (int) config('filagora-plugins-security.analyzers.clamav.timeout_seconds', 300);

        $args = [$binary, '--infected', '--no-summary', '--recursive'];
        if (str_ends_with($binary, 'clamdscan')) {
            // Let the daemon (which may run as a different user) read the files.
            array_splice($args, 1, 0, '--fdpass');
        }
        $args[] = $context->extractedPath;

        $result = Process::timeout($timeout)->run($args);

        // 0 = clean, 1 = infected, 2 = error.
        if ($result->exitCode() === 2 || ($result->exitCode() !== 0 && $result->exitCode() !== 1)) {
            return AnalyzerResult::failed('ClamAV error: '.trim($result->errorOutput() ?: $result->output()));
        }

        $findings = [];
        foreach (preg_split('/\R/', $result->output()) ?: [] as $line) {
            if (! str_ends_with(trim($line), 'FOUND')) {
                continue;
            }

            // "/tmp/plugin-scan-xxxx/foo/bar.php: Win.Test.EICAR_HDB-1 FOUND"
            [$path, $rest] = array_pad(explode(':', $line, 2), 2, '');
            $signature = trim(preg_replace('/\s+FOUND$/', '', trim($rest)) ?? 'unknown');

            $findings[] = new ScanFinding(
                $this->name(),
                'clamav-'.Str::slug($signature ?: 'signature'),
                ScanSeverity::CRITICAL,
                'ClamAV signature match: '.$signature,
                $this->relativePath($context, trim($path)),
            );
        }

        return AnalyzerResult::completed($findings);
    }

    /**
     * The configured ClamAV binary if it runs, else the first of
     * clamdscan / clamscan that does, else null.
     */
    private function binary(): ?string
    {
        if ($this->resolvedBinary !== null) {
            return $this->resolvedBinary ?: null;
        }

        $candidates = array_values(array_unique(array_filter([
            (string) config('filagora-plugins-security.analyzers.clamav.binary', 'clamdscan'),
            'clamdscan',
            'clamscan',
        ])));

        foreach ($candidates as $candidate) {
            if (Process::timeout(10)->run([$candidate, '--version'])->successful()) {
                return $this->resolvedBinary = $candidate;
            }
        }

        $this->resolvedBinary = '';

        return null;
    }

    private function relativePath(ScanContext $context, string $absolute): ?string
    {
        if ($absolute === '' || ! str_starts_with($absolute, $context->extractedPath)) {
            return $absolute !== '' ? $absolute : null;
        }

        return ltrim(substr($absolute, strlen($context->extractedPath)), '/') ?: null;
    }
}
