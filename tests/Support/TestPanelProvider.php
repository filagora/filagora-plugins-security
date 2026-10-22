<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Support;

use Filagora\Core\FilagoraCorePlugin;
use Filagora\Plugins\FilagoraPluginsPlugin;
use Filagora\PluginsSecurity\FilagoraPluginsSecurityPlugin;
use Filament\Panel;
use Filament\PanelProvider;

class TestPanelProvider extends PanelProvider
{
    public function panel(Panel $panel): Panel
    {
        return $panel
            ->default()
            ->id('admin')
            ->path('admin')
            ->plugin(FilagoraCorePlugin::make())
            ->plugin(FilagoraPluginsPlugin::make())
            ->plugin(FilagoraPluginsSecurityPlugin::make());
    }
}
