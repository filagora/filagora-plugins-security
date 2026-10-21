<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Entitlements;

use Filagora\Entitlements\EntitlementsServiceProvider;
use Filagora\PluginsSecurity\Tests\TestCase;

/**
 * The test application with entitlements installed too, for the definition the package declares.
 */
abstract class EntitlementsTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [...parent::getPackageProviders($app), EntitlementsServiceProvider::class];
    }
}
