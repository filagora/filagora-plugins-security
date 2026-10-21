<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis\Analyzers;

use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Analysis\ScanFinding;
use Filagora\PluginsSecurity\Contracts\ReleaseAnalyzer;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Illuminate\Support\Facades\Process;
use SplFileInfo;

/**
 * Dependency-free static inspection of an extracted release:
 *
 * - `php -l` syntax check on every PHP source file (syntax only — the code
 *   is never executed);
 * - a token-based dangerous-construct scan (not regex), so `system` in a
 *   comment or string does not flag while a real `system(` call does;
 * - raw-text obfuscation heuristics (base64+eval chains, `preg_replace` /e);
 * - non-PHP red flags (`.phar`, `.htaccess` PHP handlers, image/PHP
 *   polyglots);
 * - known-bad file SHA-256 matches from config.
 *
 * A full AST pass (nikic/php-parser) is a later enhancement; the tokenizer
 * already removes the bulk of the regex scanner's false positives.
 */
class StaticPhpAnalyzer implements ReleaseAnalyzer
{
    /** Bump when the rules below change. */
    public const VERSION = 1;

    private const PHP_EXTENSIONS = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phps', 'inc'];

    /**
     * Function name (lowercase) => [rule id, severity]. Matched only when the
     * token is a bare call: `name` T_STRING immediately followed by `(`.
     *
     * @var array<string, array{0: string, 1: ScanSeverity}>
     */
    private const DANGEROUS_CALLS = [
        'exec' => ['exec-call', ScanSeverity::HIGH],
        'shell_exec' => ['shell-exec-call', ScanSeverity::HIGH],
        'system' => ['system-call', ScanSeverity::HIGH],
        'passthru' => ['passthru-call', ScanSeverity::HIGH],
        'popen' => ['popen-call', ScanSeverity::HIGH],
        'proc_open' => ['proc-open-call', ScanSeverity::HIGH],
        'pcntl_exec' => ['pcntl-exec-call', ScanSeverity::HIGH],
        'assert' => ['assert-call', ScanSeverity::MEDIUM],
        'create_function' => ['create-function-call', ScanSeverity::HIGH],
        'dl' => ['dl-call', ScanSeverity::HIGH],
    ];

    public function name(): string
    {
        return 'static_php';
    }

    public function version(): string
    {
        return (string) self::VERSION;
    }

    public function isAvailable(): bool
    {
        return (bool) config('filagora-plugins-security.analyzers.static_php.enabled', true)
            && function_exists('token_get_all');
    }

    public function analyze(ScanContext $context): AnalyzerResult
    {
        $config = (array) config('filagora-plugins-security.analyzers.static_php', []);
        $maxFiles = (int) ($config['max_files'] ?? 2000);
        $lintTimeout = (int) ($config['timeout_seconds'] ?? 5);
        $phpBinary = (string) ($config['php_binary'] ?? PHP_BINARY);
        /** @var list<string> $knownBad */
        $knownBad = array_map('strtolower', (array) ($config['known_bad_sha256'] ?? []));

        $findings = [];
        $filesChecked = 0;

        foreach ($context->files() as $file) {
            if ($filesChecked >= $maxFiles) {
                break;
            }
            $filesChecked++;

            $relative = $context->relativePath($file);
            $contents = @file_get_contents($file->getPathname());
            if ($contents === false) {
                continue;
            }

            if ($knownBad !== []) {
                $hash = strtolower(hash('sha256', $contents));
                if (in_array($hash, $knownBad, true)) {
                    $findings[] = new ScanFinding(
                        $this->name(), 'known-bad-hash', ScanSeverity::CRITICAL,
                        'File matches a known-malicious SHA-256', $relative, null, $hash,
                    );

                    continue;
                }
            }

            foreach ($this->inspectFile($file, $relative, $contents, $phpBinary, $lintTimeout) as $finding) {
                $findings[] = $finding;
            }
        }

        return AnalyzerResult::completed($findings);
    }

    /**
     * @return list<ScanFinding>
     */
    private function inspectFile(SplFileInfo $file, string $relative, string $contents, string $phpBinary, int $lintTimeout): array
    {
        $extension = strtolower($file->getExtension());
        $basename = strtolower($file->getFilename());
        $findings = [];

        if ($extension === 'phar') {
            $findings[] = new ScanFinding(
                $this->name(), 'phar-archive', ScanSeverity::HIGH,
                'Ships a PHAR archive', $relative,
            );
        }

        if ($basename === '.htaccess' && preg_match('/\b(php_value|php_flag|SetHandler|AddHandler|AddType)\b/i', $contents) === 1) {
            $findings[] = new ScanFinding(
                $this->name(), 'htaccess-php-handler', ScanSeverity::MEDIUM,
                '.htaccess sets a PHP handler or ini value', $relative,
            );
        }

        if (in_array($extension, self::PHP_EXTENSIONS, true)) {
            if ($this->looksLikePolyglot($contents)) {
                $findings[] = new ScanFinding(
                    $this->name(), 'php-image-polyglot', ScanSeverity::CRITICAL,
                    'PHP file begins with image magic bytes (polyglot)', $relative, 1,
                );
            }

            $syntax = $this->syntaxError($contents, $relative, $phpBinary, $lintTimeout);
            if ($syntax !== null) {
                $findings[] = $syntax;
            }

            foreach ($this->tokenScan($contents, $relative) as $finding) {
                $findings[] = $finding;
            }

            foreach ($this->rawHeuristics($contents, $relative) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    private function looksLikePolyglot(string $contents): bool
    {
        $head = substr($contents, 0, 8);

        return str_starts_with($head, 'GIF87a')
            || str_starts_with($head, 'GIF89a')
            || str_starts_with($head, "\x89PNG\r\n\x1a\n")
            || str_starts_with($head, "\xFF\xD8\xFF");
    }

    private function syntaxError(string $contents, string $relative, string $phpBinary, int $timeout): ?ScanFinding
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'filagora-lint-');
        if (! is_string($tempPath)) {
            return null;
        }

        try {
            file_put_contents($tempPath, $contents);
            $result = Process::timeout($timeout)->run([$phpBinary, '-l', $tempPath]);

            // `php -l` exits 255 for a file it cannot parse. Anything else that fails (a missing
            // or wrong binary) says nothing about the file, so it is not reported as its fault.
            if ($result->exitCode() !== 255) {
                return null;
            }

            $message = trim($result->errorOutput()) !== '' ? trim($result->errorOutput()) : trim($result->output());
            $message = str_replace($tempPath, $relative, $message);
            $firstLine = strtok($message, "\n");

            return new ScanFinding(
                $this->name(), 'php-syntax-error', ScanSeverity::MEDIUM,
                is_string($firstLine) ? $firstLine : 'PHP syntax error', $relative,
            );
        } finally {
            @unlink($tempPath);
        }
    }

    /**
     * @return list<ScanFinding>
     */
    private function tokenScan(string $contents, string $relative): array
    {
        $tokens = @token_get_all($contents);

        $findings = [];
        $count = count($tokens);
        $inBackticks = false;

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            // `eval` is a language construct: T_EVAL, not T_STRING.
            if (is_array($token) && $token[0] === T_EVAL) {
                $findings[] = new ScanFinding(
                    $this->name(), 'eval-construct', ScanSeverity::HIGH,
                    'Uses eval()', $relative, (int) $token[2],
                );

                continue;
            }

            // Backtick shell execution. The operator is a backtick on each side of the command, so
            // only the one that opens it counts.
            if ($token === '`') {
                $inBackticks = ! $inBackticks;

                if ($inBackticks) {
                    $findings[] = new ScanFinding(
                        $this->name(), 'backtick-exec', ScanSeverity::HIGH,
                        'Uses the backtick shell-execution operator', $relative,
                        isset($tokens[$i - 1][2]) ? (int) $tokens[$i - 1][2] : null,
                    );
                }

                continue;
            }

            if (! is_array($token) || $token[0] !== T_STRING) {
                continue;
            }

            $name = strtolower($token[1]);
            if (! isset(self::DANGEROUS_CALLS[$name])) {
                continue;
            }

            // Only flag a call: next significant token is "(". Skips method
            // calls / property access (preceded by -> or ::) and use/function
            // declarations.
            $prev = $this->previousSignificant($tokens, $i);
            if (is_array($prev) && in_array($prev[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NULLSAFE_OBJECT_OPERATOR], true)) {
                continue;
            }

            $next = $this->nextSignificant($tokens, $i);
            if ($next !== '(') {
                continue;
            }

            [$ruleId, $severity] = self::DANGEROUS_CALLS[$name];
            $findings[] = new ScanFinding(
                $this->name(), $ruleId, $severity,
                "Calls {$name}()", $relative, (int) $token[2],
            );
        }

        return $findings;
    }

    /**
     * @return list<ScanFinding>
     */
    private function rawHeuristics(string $contents, string $relative): array
    {
        $findings = [];

        if (preg_match('/preg_replace\s*\(\s*([\'"]).*?\1\s*\.\s*[\'"]e|preg_replace\s*\(\s*[\'"][^\'"]*[\'"]e[imsxADSUXJu]*[\'"]/i', $contents) === 1
            || preg_match('/preg_replace\s*\(\s*[\'"].*\/e[a-z]*[\'"]/i', $contents) === 1) {
            $findings[] = new ScanFinding(
                $this->name(), 'preg-replace-eval', ScanSeverity::HIGH,
                'preg_replace() with the /e (eval) modifier', $relative,
            );
        }

        $hasDecode = preg_match('/\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|convert_uudecode)\s*\(/i', $contents) === 1;
        $hasExec = preg_match('/\b(eval|assert|create_function|call_user_func|preg_replace)\s*\(/i', $contents) === 1
            || preg_match('/\$[a-z_][a-z0-9_]*\s*\(/i', $contents) === 1;

        if ($hasDecode && $hasExec) {
            $findings[] = new ScanFinding(
                $this->name(), 'obfuscated-payload', ScanSeverity::HIGH,
                'Decode function feeding a dynamic execution call (possible obfuscated payload)', $relative,
            );
        }

        return $findings;
    }

    /**
     * @param  array<int, array{0:int,1:string,2:int}|string>  $tokens
     * @return array{0:int,1:string,2:int}|string|null
     */
    private function nextSignificant(array $tokens, int $index): array|string|null
    {
        for ($i = $index + 1, $count = count($tokens); $i < $count; $i++) {
            if (is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return $tokens[$i];
        }

        return null;
    }

    /**
     * @param  array<int, array{0:int,1:string,2:int}|string>  $tokens
     * @return array{0:int,1:string,2:int}|string|null
     */
    private function previousSignificant(array $tokens, int $index): array|string|null
    {
        for ($i = $index - 1; $i >= 0; $i--) {
            if (is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return $tokens[$i];
        }

        return null;
    }
}
