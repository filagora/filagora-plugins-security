<?php

declare(strict_types=1);

use Filagora\Core\Support\Tables;
use Filagora\Core\Support\UserKey;
use Filagora\Core\Support\UserModel;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * The scan record and the moderator's accepted findings, in the shape of the site this was
 * extracted from, and then the two foreign keys from `plugin_releases` to a scan. The plugins
 * package ships those two columns as plain, indexed columns so it installs on its own; this is the
 * package that owns what they point at.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::name('plugin_release_security_scans'), function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('plugin_release_id');
            $table->string('kind', 16)->default('standard');
            $table->unsignedInteger('scanner_version');
            $table->json('analyzer_versions')->nullable();
            $table->string('status', 16)->default('pending');
            $table->string('highest_severity', 16)->nullable();
            $table->json('finding_counts')->nullable();
            $table->json('findings')->nullable();
            $table->string('triggered_by', 16);
            UserKey::column($table, 'triggered_by_user_id')->nullable();
            $table->timestamp('queued_at')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->text('error')->nullable();
            $table->timestamps();

            $table->index('triggered_by_user_id', 'plugin_release_security_scans_triggered_by_user_id_foreign');
            $table->index(['plugin_release_id', 'id'], 'prss_release_latest_idx');
            $table->index(['plugin_release_id', 'scanner_version'], 'prss_release_version_idx');
            $table->index('status', 'prss_status_idx');
            $table->index(['plugin_release_id', 'kind', 'id'], 'prss_release_kind_idx');

            $table->foreign('plugin_release_id', 'plugin_release_security_scans_plugin_release_id_foreign')
                ->references('id')->on(Tables::name('plugin_releases'))->cascadeOnDelete();
            $table->foreign('triggered_by_user_id', 'plugin_release_security_scans_triggered_by_user_id_foreign')
                ->references('id')->on(UserModel::table())->nullOnDelete();
        });

        Schema::create(Tables::name('plugin_release_scan_finding_reviews'), function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('plugin_id');
            $table->string('fingerprint', 32);
            UserKey::column($table, 'reviewed_by_id')->nullable();
            $table->text('note')->nullable();
            $table->timestamps();

            $table->unique(['plugin_id', 'fingerprint'], 'prsfr_plugin_fingerprint_unique');
            $table->index('reviewed_by_id', 'plugin_release_scan_finding_reviews_reviewed_by_id_foreign');

            $table->foreign('plugin_id', 'plugin_release_scan_finding_reviews_plugin_id_foreign')
                ->references('id')->on(Tables::name('plugins'))->cascadeOnDelete();
            $table->foreign('reviewed_by_id', 'plugin_release_scan_finding_reviews_reviewed_by_id_foreign')
                ->references('id')->on(UserModel::table())->nullOnDelete();
        });

        Schema::table(Tables::name('plugin_releases'), function (Blueprint $table): void {
            $table->foreign('latest_security_scan_id', 'plugin_releases_latest_security_scan_id_foreign')
                ->references('id')->on(Tables::name('plugin_release_security_scans'))->nullOnDelete();
            $table->foreign('quarantine_scan_id', 'plugin_releases_quarantine_scan_id_foreign')
                ->references('id')->on(Tables::name('plugin_release_security_scans'))->nullOnDelete();
        });
    }

    public function down(): void
    {
        Schema::table(Tables::name('plugin_releases'), function (Blueprint $table): void {
            $table->dropForeign('plugin_releases_latest_security_scan_id_foreign');
            $table->dropForeign('plugin_releases_quarantine_scan_id_foreign');
        });

        Schema::dropIfExists(Tables::name('plugin_release_scan_finding_reviews'));
        Schema::dropIfExists(Tables::name('plugin_release_security_scans'));
    }
};
