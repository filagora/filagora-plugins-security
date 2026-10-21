<?php

declare(strict_types=1);

use Filagora\Core\Support\GateAbilities;
use Filagora\Entitlements\Registry\EntitlementRegistry;

/*
 * The database may already have been built, without entitlements, by an earlier test, so this test
 * brings the entitlement tables up to date itself.
 */
beforeEach(function () {
    $this->artisan('migrate')->assertSuccessful();
});

it('declares the key behind its ability, without letting it cover what is below it', function () {
    $definitions = app(EntitlementRegistry::class)->definitions();

    expect($definitions)->toHaveKey('filagora.plugins.security')
        ->and($definitions['filagora.plugins.security']->wildcardChildren)->toBeFalse();
});

it('declares the key a host has remapped the ability to', function () {
    expect(GateAbilities::keys('filagora-plugins-security.gates'))->toBe(['filagora.plugins.security']);
});
