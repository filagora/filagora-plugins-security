<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Support;

use Illuminate\Support\ServiceProvider;

use function Orchestra\Testbench\default_migration_path;

/**
 * Registers Laravel's default migrations (the users table) the way a package would,
 * so they sit in the same migration run as the package's own and need no per-test
 * rollback, which would fail on foreign keys into users.
 */
class TestSupportServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->loadMigrationsFrom(default_migration_path());
    }
}
