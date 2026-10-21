<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Scanner
    |--------------------------------------------------------------------------
    |
    | `version` is the composite scanner version. Raise it whenever the analyzers or their rules
    | change: a release whose latest scan used an older version is stale and the sweep re-scans it.
    | `queue` is the queue scan jobs go to (null for the default one); a scan can run for minutes
    | once ClamAV or Semgrep are on, so a host may want a worker of its own. `dispatch_on_upload`
    | queues a scan when a release is submitted. `quarantine_threshold` is the lowest severity that
    | quarantines a release (info, low, medium, high or critical), and `auto_clear_when_clean` lifts
    | a quarantine when a re-scan finds nothing.
    |
    */
    'scanner' => [
        'version' => (int) env('FILAGORA_PLUGINS_SECURITY_VERSION', 1),
        'queue' => env('FILAGORA_PLUGINS_SECURITY_QUEUE'),
        'timeout_seconds' => (int) env('FILAGORA_PLUGINS_SECURITY_TIMEOUT_SECONDS', 600),
        'dispatch_on_upload' => (bool) env('FILAGORA_PLUGINS_SECURITY_DISPATCH_ON_UPLOAD', true),
        'quarantine_threshold' => env('FILAGORA_PLUGINS_SECURITY_QUARANTINE_THRESHOLD', 'critical'),
        'auto_clear_when_clean' => (bool) env('FILAGORA_PLUGINS_SECURITY_AUTO_CLEAR_WHEN_CLEAN', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Archiving
    |--------------------------------------------------------------------------
    |
    | Old releases are archived by `filagora:plugins:archive-releases`. A release whose latest scan
    | still holds a finding at or above `keep_at_severity` that no moderator has accepted is kept
    | active, so it stays in front of staff. Set it to null to have no say.
    |
    */
    'archive' => [
        'keep_at_severity' => env('FILAGORA_PLUGINS_SECURITY_KEEP_AT_SEVERITY', 'high'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Analyzers
    |--------------------------------------------------------------------------
    |
    | Each one is switched on or off here and says where its binary is and how long it may run. The
    | static PHP checks need nothing installed. ClamAV and Semgrep are off until their binaries are.
    | An analyzer that is off, or whose binary is missing, is recorded as skipped and never fails a
    | scan. The language-model review is advisory and runs only when staff ask for it; it needs a
    | `LlmReviewer` bound by the host.
    |
    */
    'analyzers' => [
        'static_php' => [
            'enabled' => (bool) env('FILAGORA_PLUGINS_SECURITY_STATIC_PHP_ENABLED', true),
            'max_files' => (int) env('FILAGORA_PLUGINS_SECURITY_STATIC_PHP_MAX_FILES', 2000),
            'timeout_seconds' => (int) env('FILAGORA_PLUGINS_SECURITY_STATIC_PHP_TIMEOUT_SECONDS', 5),
            // The CLI interpreter that runs `php -l`. In a web request PHP_BINARY is the FPM
            // binary, which cannot lint, so fall back to `php` from the path.
            'php_binary' => env('FILAGORA_PLUGINS_SECURITY_PHP_BINARY') ?: (PHP_SAPI === 'cli' ? PHP_BINARY : 'php'),
            // Comma-separated SHA-256 hashes of files known to be malicious.
            'known_bad_sha256' => array_values(array_filter(array_map(
                'trim',
                explode(',', (string) env('FILAGORA_PLUGINS_SECURITY_KNOWN_BAD_SHA256', '')),
            ))),
        ],
        'clamav' => [
            'enabled' => (bool) env('FILAGORA_PLUGINS_SECURITY_CLAMAV_ENABLED', false),
            'binary' => env('FILAGORA_PLUGINS_SECURITY_CLAMAV_BINARY', 'clamdscan'),
            'timeout_seconds' => (int) env('FILAGORA_PLUGINS_SECURITY_CLAMAV_TIMEOUT_SECONDS', 300),
        ],
        'semgrep' => [
            'enabled' => (bool) env('FILAGORA_PLUGINS_SECURITY_SEMGREP_ENABLED', false),
            'binary' => env('FILAGORA_PLUGINS_SECURITY_SEMGREP_BINARY', 'semgrep'),
            // A rules file or a directory of them; null uses the rules shipped with the package.
            'ruleset_path' => env('FILAGORA_PLUGINS_SECURITY_SEMGREP_RULESET_PATH'),
            'timeout_seconds' => (int) env('FILAGORA_PLUGINS_SECURITY_SEMGREP_TIMEOUT_SECONDS', 300),
        ],
        'llm' => [
            'enabled' => (bool) env('FILAGORA_PLUGINS_SECURITY_LLM_ENABLED', false),
            // What the reviewer is told the plugins are for ("a security reviewer for ...").
            'subject' => env('FILAGORA_PLUGINS_SECURITY_LLM_SUBJECT', 'plugins'),
            'max_files' => (int) env('FILAGORA_PLUGINS_SECURITY_LLM_MAX_FILES', 150),
            'max_file_bytes' => (int) env('FILAGORA_PLUGINS_SECURITY_LLM_MAX_FILE_BYTES', 60000),
            // Source bytes in one request; the files are batched under this.
            'max_batch_bytes' => (int) env('FILAGORA_PLUGINS_SECURITY_LLM_MAX_BATCH_BYTES', 120000),
            'max_batches' => (int) env('FILAGORA_PLUGINS_SECURITY_LLM_MAX_BATCHES', 6),
            // Per request, for the job's own time limit; the host's client enforces its own.
            'timeout_seconds' => (int) env('FILAGORA_PLUGINS_SECURITY_LLM_TIMEOUT_SECONDS', 600),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Sweep
    |--------------------------------------------------------------------------
    |
    | `filagora:plugins:security-sweep` re-scans active releases left stale by a version bump, in a
    | small batch so a bump does not drop dozens of minutes-long scans at once. Schedule it (every
    | half an hour suits). `enabled` switches it off without unscheduling it.
    |
    */
    'sweep' => [
        'enabled' => (bool) env('FILAGORA_PLUGINS_SECURITY_SWEEP_ENABLED', true),
        'batch_size' => (int) env('FILAGORA_PLUGINS_SECURITY_SWEEP_BATCH_SIZE', 4),
    ],

    /*
    |--------------------------------------------------------------------------
    | Mail
    |--------------------------------------------------------------------------
    |
    | `enabled` switches the default emails off (listen to the package's events instead). Staff
    | alerts go to `filagora-plugins.mail.support_email`.
    |
    */
    'mail' => [
        'enabled' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Gates
    |--------------------------------------------------------------------------
    |
    | The ability that sees scans, re-scans, quarantines and clears, and accepts a finding, and the
    | access key behind it (`ability => key`). Remap a key here; the ability keeps its name.
    |
    */
    'gates' => [
        'filagora.plugins.security' => 'filagora.plugins.security',
    ],

];
