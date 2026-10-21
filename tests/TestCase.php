<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests;

use BladeUI\Heroicons\BladeHeroiconsServiceProvider;
use BladeUI\Icons\BladeIconsServiceProvider;
use Filagora\Core\Contracts\AccessChecker;
use Filagora\Core\CoreServiceProvider;
use Filagora\Plugins\PluginsServiceProvider;
use Filagora\PluginsSecurity\PluginsSecurityServiceProvider;
use Filagora\PluginsSecurity\Tests\Support\GrantedKeys;
use Filagora\PluginsSecurity\Tests\Support\TestSupportServiceProvider;
use Filagora\PluginsSecurity\Tests\Support\TestUser;
use Filament\Actions\ActionsServiceProvider;
use Filament\FilamentServiceProvider;
use Filament\Forms\FormsServiceProvider;
use Filament\Infolists\InfolistsServiceProvider;
use Filament\Notifications\NotificationsServiceProvider;
use Filament\Schemas\SchemasServiceProvider;
use Filament\Support\SupportServiceProvider;
use Filament\Tables\TablesServiceProvider;
use Filament\Widgets\WidgetsServiceProvider;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            ActionsServiceProvider::class,
            BladeHeroiconsServiceProvider::class,
            BladeIconsServiceProvider::class,
            FilamentServiceProvider::class,
            FormsServiceProvider::class,
            InfolistsServiceProvider::class,
            LivewireServiceProvider::class,
            NotificationsServiceProvider::class,
            SchemasServiceProvider::class,
            SupportServiceProvider::class,
            TablesServiceProvider::class,
            WidgetsServiceProvider::class,
            CoreServiceProvider::class,
            PluginsServiceProvider::class,
            PluginsSecurityServiceProvider::class,
            TestSupportServiceProvider::class,
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->singleton(GrantedKeys::class);
        $this->app->bind(AccessChecker::class, GrantedKeys::class);
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('filagora.user_model', TestUser::class);
        $app['config']->set('auth.providers.users.model', TestUser::class);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        // Scans are queued by default; in tests the queue is sync, so tests that upload would scan.
        $app['config']->set('filagora-plugins-security.scanner.dispatch_on_upload', false);
    }
}
