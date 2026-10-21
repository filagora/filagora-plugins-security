<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity;

use Filagora\Core\Modules\Module;
use Filagora\Core\Modules\ModuleRegistry;
use Filagora\Core\Schema\PackageSchema;
use Filagora\Core\Schema\SchemaExtension;
use Filagora\Core\Schema\SchemaRegistry;
use Filagora\Core\Support\GateAbilities;
use Filagora\Entitlements\Registry\Definition;
use Filagora\Entitlements\Registry\EntitlementRegistry;
use Filagora\Plugins\Archiving\ArchiveGuards;
use Filagora\Plugins\Events\ReleaseSubmitted;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Support\Models;
use Filagora\PluginsSecurity\Analysis\Analyzers;
use Filagora\PluginsSecurity\Analysis\Analyzers\ClamavAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\LlmAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\SemgrepAnalyzer;
use Filagora\PluginsSecurity\Analysis\Analyzers\StaticPhpAnalyzer;
use Filagora\PluginsSecurity\Console\SecurityScanCommand;
use Filagora\PluginsSecurity\Console\SecuritySweepCommand;
use Filagora\PluginsSecurity\Contracts\LlmReviewer;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Events\LlmReviewFinished;
use Filagora\PluginsSecurity\Events\QuarantineCleared;
use Filagora\PluginsSecurity\Events\ReleaseQuarantined;
use Filagora\PluginsSecurity\Events\ScanFinished;
use Filagora\PluginsSecurity\Events\SeriousFindingFlagged;
use Filagora\PluginsSecurity\Listeners\QueueScanOnSubmission;
use Filagora\PluginsSecurity\Listeners\SendSecurityMail;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\AcceptedFindings;
use Filagora\PluginsSecurity\Services\FindingReviews;
use Filagora\PluginsSecurity\Services\LlmReviews;
use Filagora\PluginsSecurity\Services\Quarantine;
use Filagora\PluginsSecurity\Services\Scanner;
use Filagora\PluginsSecurity\Support\NoLlmReviewer;
use Filagora\PluginsSecurity\Support\ReleaseArchives;
use Filagora\PluginsSecurity\Support\SeriousFindingGuard;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class PluginsSecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/filagora-plugins-security.php', 'filagora-plugins-security');

        $this->app->bindIf(LlmReviewer::class, NoLlmReviewer::class);
        $this->app->singleton(Analyzers::class, function ($app): Analyzers {
            $analyzers = new Analyzers;

            foreach ([StaticPhpAnalyzer::class, ClamavAnalyzer::class, SemgrepAnalyzer::class] as $analyzer) {
                $analyzers->register($app->make($analyzer));
            }

            return $analyzers;
        });
        $this->app->singleton(ReleaseArchives::class);
        $this->app->singleton(AcceptedFindings::class);
        $this->app->singleton(FindingReviews::class);
        $this->app->singleton(Quarantine::class);
        $this->app->singleton(Scanner::class);
        $this->app->singleton(LlmAnalyzer::class);
        $this->app->singleton(LlmReviews::class);
    }

    public function boot(): void
    {
        $this->app->make(ModuleRegistry::class)->register(
            new Module('plugins-security', 'Filagora Plugins Security', 'filagora/filagora-plugins-security', requires: ['core', 'plugins']),
        );

        $registry = $this->app->make(SchemaRegistry::class);
        $registry->register(PackageSchema::fromFile('plugins-security', __DIR__.'/../database/schema.php', __DIR__.'/../database/migrations'));
        $registry->extend(SchemaExtension::fromFile('plugins-security', 'plugins', __DIR__.'/../database/extensions/plugins.php'));

        GateAbilities::define('filagora-plugins-security.gates');

        $this->registerReleaseRelations();

        $this->app->make(ArchiveGuards::class)->register($this->app->make(SeriousFindingGuard::class));

        Event::listen(ReleaseSubmitted::class, QueueScanOnSubmission::class);
        Event::listen(ScanFinished::class, [SendSecurityMail::class, 'scanFinished']);
        Event::listen(ReleaseQuarantined::class, [SendSecurityMail::class, 'quarantined']);
        Event::listen(QuarantineCleared::class, [SendSecurityMail::class, 'cleared']);
        Event::listen(SeriousFindingFlagged::class, [SendSecurityMail::class, 'flagged']);
        Event::listen(LlmReviewFinished::class, [SendSecurityMail::class, 'reviewFinished']);

        $this->declareEntitlements();

        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'filagora-plugins-security');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([SecurityScanCommand::class, SecuritySweepCommand::class]);

            $this->publishes([
                __DIR__.'/../config/filagora-plugins-security.php' => config_path('filagora-plugins-security.php'),
            ], 'filagora-plugins-security-config');
        }
    }

    /**
     * A release answers for its scans. The relations are added to whichever model the host has
     * chosen for releases, so they follow a swapped model.
     */
    private function registerReleaseRelations(): void
    {
        $release = Models::class('release');

        $release::resolveRelationUsing('securityScans', static fn (PluginRelease $model): HasMany => $model->hasMany(SecurityScan::class, 'plugin_release_id')->latest('id'));
        $release::resolveRelationUsing('latestSecurityScan', static fn (PluginRelease $model): BelongsTo => $model->belongsTo(SecurityScan::class, 'latest_security_scan_id'));
        $release::resolveRelationUsing('quarantineScan', static fn (PluginRelease $model): BelongsTo => $model->belongsTo(SecurityScan::class, 'quarantine_scan_id'));
        // Not the latest_security_scan_id pointer, which only the standard pipeline moves.
        $release::resolveRelationUsing('latestLlmReview', static fn (PluginRelease $model): HasOne => $model->hasOne(SecurityScan::class, 'plugin_release_id')->where('kind', ScanKind::LLM->value)->latestOfMany());
    }

    /**
     * With `filagora-entitlements` installed, the key behind the ability is declared so
     * `filagora:entitlements:sync` creates its definition.
     */
    private function declareEntitlements(): void
    {
        if (! class_exists(EntitlementRegistry::class) || ! $this->app->bound(EntitlementRegistry::class)) {
            return;
        }

        $registry = $this->app->make(EntitlementRegistry::class);

        foreach (GateAbilities::keys('filagora-plugins-security.gates') as $entitlement) {
            $registry->define(new Definition($entitlement, wildcardChildren: false));
        }
    }
}
