<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity;

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

    public function register(Panel $panel): void
    {
        //
    }

    public function boot(Panel $panel): void
    {
        //
    }
}
