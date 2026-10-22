<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity;

use Filagora\Plugins\Filament\ReleaseScreens;
use Filagora\PluginsSecurity\Filament\RelationManagers\SecurityScansRelationManager;
use Filagora\PluginsSecurity\Filament\ReleaseScreenParts;
use Filagora\PluginsSecurity\Filament\SecurityActions;
use Filament\Contracts\Plugin;
use Filament\Panel;

class FilagoraPluginsSecurityPlugin implements Plugin
{
    public static function make(): static
    {
        return app(static::class);
    }

    public function getId(): string
    {
        return 'filagora-plugins-security';
    }

    /**
     * Puts the scan result, the filters, the actions and the scan history on the release screens of
     * the plugins package. Each is keyed, so adding the plugin to several panels adds them once.
     */
    public function register(Panel $panel): void
    {
        $screens = app(ReleaseScreens::class);

        $screens->column('security.severity', fn () => ReleaseScreenParts::severityColumn());
        $screens->column('security.version', fn () => ReleaseScreenParts::versionColumn());
        $screens->filter('security.severity', fn () => ReleaseScreenParts::severityFilter());
        $screens->filter('security.version', fn () => ReleaseScreenParts::versionFilter());
        $screens->action('security.latest', fn () => SecurityActions::latestScan());
        $screens->action('security.review', fn () => SecurityActions::latestReview());
        $screens->action('security.more', fn () => SecurityActions::more());
        $screens->bulkAction('security.rescan', fn () => SecurityActions::rescanSeveral());
        $screens->relationManager('security.scans', SecurityScansRelationManager::class);
    }

    public function boot(Panel $panel): void
    {
        //
    }
}
