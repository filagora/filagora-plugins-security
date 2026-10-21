<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Models;

use Filagora\Core\Support\Tables;
use Filagora\Core\Support\UserModel;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\Plugins\Support\Models;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One immutable record of a scan of a release. `findings` holds the analyzers' results and
 * `scanner_version` which version of the scanner produced them, so a re-scan can be aimed at the
 * releases last checked by an older one.
 *
 * @property int $id
 * @property int $plugin_release_id
 * @property ScanKind $kind
 * @property int $scanner_version
 * @property array<string, array<string, mixed>>|null $analyzer_versions
 * @property ScanStatus $status
 * @property ScanSeverity|null $highest_severity
 * @property array<string, int>|null $finding_counts
 * @property list<array<string, mixed>>|null $findings
 * @property ScanTrigger $triggered_by
 * @property int|null $triggered_by_user_id
 * @property Carbon|null $queued_at
 * @property Carbon|null $started_at
 * @property Carbon|null $finished_at
 * @property string|null $error
 */
class SecurityScan extends Model
{
    protected $fillable = [
        'plugin_release_id',
        'kind',
        'scanner_version',
        'analyzer_versions',
        'status',
        'highest_severity',
        'finding_counts',
        'findings',
        'triggered_by',
        'triggered_by_user_id',
        'queued_at',
        'started_at',
        'finished_at',
        'error',
    ];

    public function getTable(): string
    {
        return Tables::name('plugin_release_security_scans');
    }

    protected function casts(): array
    {
        return [
            'kind' => ScanKind::class,
            'scanner_version' => 'integer',
            'analyzer_versions' => 'array',
            'finding_counts' => 'array',
            'findings' => 'array',
            'status' => ScanStatus::class,
            'highest_severity' => ScanSeverity::class,
            'triggered_by' => ScanTrigger::class,
            'queued_at' => 'datetime',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<PluginRelease, $this>
     */
    public function release(): BelongsTo
    {
        return $this->belongsTo(Models::class('release'), 'plugin_release_id');
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function triggeredByUser(): BelongsTo
    {
        return $this->belongsTo(UserModel::class(), 'triggered_by_user_id');
    }

    public function isFinished(): bool
    {
        return $this->status->isFinished();
    }

    public function severity(): ScanSeverity
    {
        return $this->highest_severity ?? ScanSeverity::NONE;
    }

    public function hasFindingAtLeast(ScanSeverity $threshold): bool
    {
        return $this->status === ScanStatus::COMPLETED
            && $this->severity() !== ScanSeverity::NONE
            && $this->severity()->isAtLeast($threshold);
    }

    public function findingCount(ScanSeverity $severity): int
    {
        return (int) (($this->finding_counts ?? [])[$severity->value] ?? 0);
    }
}
