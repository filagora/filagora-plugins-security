<?php

declare(strict_types=1);

use Filagora\PluginsSecurity\Tests\Entitlements\EntitlementsTestCase;
use Filagora\PluginsSecurity\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;

require_once __DIR__.'/Support/Fixtures.php';

pest()->extend(TestCase::class)->use(RefreshDatabase::class)->in('Feature');
pest()->extend(EntitlementsTestCase::class)->use(RefreshDatabase::class)->in('Entitlements');
