<?php

declare(strict_types=1);

use Filagora\Core\Schema\SchemaRegistry;
use Filagora\Core\Schema\TableShape;
use Filagora\Core\Support\Tables;
use Filagora\PluginsSecurity\Models\FindingReview;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Illuminate\Support\Facades\Schema;

/*
 * The tables must match the site they were extracted from, so an existing site can adopt them as
 * they are. The snapshot was checked against the real table definitions by running
 * `filagora:adopt --dry-run` on them.
 */

it('ships a snapshot of the two tables that matches the migration, column order included', function () {
    $snapshot = app(SchemaRegistry::class)->get('plugins-security');

    expect(array_keys($snapshot->tables))->toBe(['plugin_release_security_scans', 'plugin_release_scan_finding_reviews'])
        ->and($snapshot->migrationNames())->toBe(['2026_10_21_000000_create_filagora_plugin_security_tables']);

    foreach ($snapshot->tables as $base => $expected) {
        expect(TableShape::inspect($base)->differencesFrom($expected, compareColumnOrder: true))->toBe([], $base);
    }
});

it('ties a release to its latest and its quarantine scan, clearing the link when a scan goes', function () {
    $foreignKeys = TableShape::inspect('plugin_releases')->foreignKeys;

    expect($foreignKeys)->toHaveKeys(['plugin_releases_latest_security_scan_id_foreign', 'plugin_releases_quarantine_scan_id_foreign'])
        ->and($foreignKeys['plugin_releases_latest_security_scan_id_foreign']['on_delete'])->toBe('set null')
        ->and($foreignKeys['plugin_releases_quarantine_scan_id_foreign']['on'])->toBe('plugin_release_security_scans');
});

it('declares those links as an extension of the plugins tables, and the tables match it', function () {
    $registry = app(SchemaRegistry::class);
    $schema = $registry->get('plugins')->extendedBy($registry->extensionsFor('plugins'));

    expect(TableShape::inspect('plugin_releases')->differencesFrom($schema->tables['plugin_releases']))->toBe([]);
});

it('keeps the keys the site relies on', function () {
    $scans = TableShape::inspect('plugin_release_scan_finding_reviews');

    expect($scans->indexes['prsfr_plugin_fingerprint_unique']['unique'])->toBeTrue()
        ->and(TableShape::inspect('plugin_release_security_scans')->columns['kind']['default'])->toBe('standard')
        ->and(TableShape::inspect('plugin_release_security_scans')->columns['status']['default'])->toBe('pending');
});

it('removes a release\'s scans with it, and a plugin\'s accepted findings with the plugin', function () {
    $release = releaseWith();
    $scan = finishedScan($release);
    $release->update(['latest_security_scan_id' => $scan->id]);
    FindingReview::create(['plugin_id' => $release->plugin_id, 'fingerprint' => 'abc']);

    $scan->delete();
    expect($release->refresh()->latest_security_scan_id)->toBeNull();

    finishedScan($release);
    $release->delete();
    expect(SecurityScan::count())->toBe(0);

    $release->plugin->delete();
    expect(FindingReview::count())->toBe(0);
});

it('uses the configured table prefix', function () {
    expect(Schema::hasTable(Tables::name('plugin_release_security_scans')))->toBeTrue()
        ->and((new SecurityScan)->getTable())->toBe(Tables::name('plugin_release_security_scans'))
        ->and((new FindingReview)->getTable())->toBe(Tables::name('plugin_release_scan_finding_reviews'));
});
