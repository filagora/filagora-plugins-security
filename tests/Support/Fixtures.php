<?php

declare(strict_types=1);

use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\Plugin;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Models\PluginType;
use Filagora\PluginsSecurity\Analysis\Analyzers;
use Filagora\PluginsSecurity\Analysis\Analyzers\LlmAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\StaticPhpAnalyzer;
use Filagora\PluginsSecurity\Contracts\LlmReviewer;
use Filagora\PluginsSecurity\Contracts\ReleaseAnalyzer;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\LlmReviews;
use Filagora\PluginsSecurity\Services\Scanner;
use Filagora\PluginsSecurity\Tests\Support\GrantedKeys;
use Filagora\PluginsSecurity\Tests\Support\TestUser;
use Filagora\PluginsSecurity\Tests\Support\Zips;
use Illuminate\Support\Facades\Storage;

function pluginType(): PluginType
{
    return PluginType::firstOrCreate(['slug' => 'tools'], ['name' => 'Tools']);
}

function securityOfficer(string $name = 'Sec'): TestUser
{
    $user = TestUser::make($name);
    app(GrantedKeys::class)->give($user, 'filagora.plugins.security');

    return $user;
}

/**
 * A plugin with one release whose archive is really stored, holding the given entries
 * (path => contents).
 *
 * @param  array<string, string>  $entries
 */
function releaseWith(array $entries = ['widget/readme.txt' => 'hello'], PluginStatus $status = PluginStatus::ACTIVE, string $slug = 'widget', ?TestUser $owner = null): PluginRelease
{
    // Once per test: faking again would empty the archives stored for the releases made before.
    if (! app()->bound('fixtures.storage')) {
        Storage::fake('local');
        app()->instance('fixtures.storage', true);
    }

    config(['filagora-plugins.storage.disk' => 'local']);

    $plugin = Plugin::query()->where('slug', $slug)->firstOr(fn (): Plugin => Plugin::create([
        'name' => ucfirst($slug),
        'slug' => $slug,
        'plugin_type_id' => pluginType()->id,
        'owner_id' => $owner?->id,
        'status' => $status,
    ]));

    $path = "plugins/{$slug}-".uniqid().'.zip';
    Storage::disk('local')->put($path, file_get_contents(Zips::make($entries)->getPathname()));

    return PluginRelease::create([
        'plugin_id' => $plugin->id,
        'uploaded_by_id' => $owner?->id,
        'version' => 'v1.0.'.PluginRelease::query()->where('plugin_id', $plugin->id)->count(),
        'zip_path' => $path,
        'status' => $status,
    ])->refresh();
}

/**
 * A finished standard scan with the given findings (severity => count is enough for most tests).
 *
 * @param  list<array<string, mixed>>  $findings
 */
function finishedScan(PluginRelease $release, ScanSeverity $severity = ScanSeverity::NONE, array $findings = [], ScanTrigger $trigger = ScanTrigger::UPLOAD, int $version = 1): SecurityScan
{
    return SecurityScan::create([
        'plugin_release_id' => $release->id,
        'scanner_version' => $version,
        'status' => ScanStatus::COMPLETED,
        'highest_severity' => $severity,
        'finding_counts' => $findings === [] ? [] : [$severity->value => count($findings)],
        'findings' => $findings,
        'triggered_by' => $trigger,
        'finished_at' => now(),
    ]);
}

/**
 * @return array<string, mixed>
 */
function finding(ScanSeverity $severity, string $fingerprint = 'abc'): array
{
    return ['analyzer' => 'static_php', 'rule_id' => 'eval-construct', 'severity' => $severity->value, 'title' => 'Uses eval()', 'file' => 'a.php', 'line' => 1, 'snippet' => null, 'fingerprint' => $fingerprint];
}

/**
 * Replace the analyzers every scan runs with the given ones.
 */
function useAnalyzers(ReleaseAnalyzer ...$analyzers): void
{
    $registry = new Analyzers;

    foreach ($analyzers as $analyzer) {
        $registry->register($analyzer);
    }

    app()->instance(Analyzers::class, $registry);
    app()->forgetInstance(Scanner::class);
}

/**
 * Only the built-in static PHP checks, which need nothing installed.
 */
function useStaticAnalyzerOnly(): void
{
    useAnalyzers(app(StaticPhpAnalyzer::class));
}

/**
 * Turn the AI review on with the given reviewer, and forget the services that took the default.
 */
function useReviewer(LlmReviewer $reviewer): void
{
    config(['filagora-plugins-security.analyzers.llm.enabled' => true]);
    app()->instance(LlmReviewer::class, $reviewer);
    app()->forgetInstance(LlmAnalyzer::class);
    app()->forgetInstance(LlmReviews::class);
}

/**
 * The reviewer's JSON reply for one finding.
 *
 * @param  array<string, mixed>  $overrides
 */
function reviewerFinding(array $overrides = []): string
{
    return json_encode([$overrides + [
        'rule_id' => 'llm.backdoor',
        'severity' => 'high',
        'title' => 'Hidden backdoor',
        'file' => 'widget/a.php',
        'line' => 2,
        'snippet' => 'eval($_POST["x"]);',
        'explanation' => 'Runs whatever the visitor sends.',
        'confidence' => 'high',
        'suggestion' => 'Remove it.',
    ]]);
}
