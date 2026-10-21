<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Models;

use Filagora\Core\Support\Tables;
use Filagora\Core\Support\UserModel;
use Filagora\Plugins\Models\Plugin;
use Filagora\Plugins\Support\Models;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A moderator's "reviewed, acceptable" for one finding, kept by the finding's fingerprint so it
 * carries to every later scan of the same plugin. A reviewed finding no longer counts toward
 * quarantine.
 *
 * @property int $id
 * @property int $plugin_id
 * @property string $fingerprint
 * @property int|null $reviewed_by_id
 * @property string|null $note
 */
class FindingReview extends Model
{
    protected $fillable = [
        'plugin_id',
        'fingerprint',
        'reviewed_by_id',
        'note',
    ];

    public function getTable(): string
    {
        return Tables::name('plugin_release_scan_finding_reviews');
    }

    /**
     * @return BelongsTo<Plugin, $this>
     */
    public function plugin(): BelongsTo
    {
        return $this->belongsTo(Models::class('plugin'), 'plugin_id');
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function reviewedBy(): BelongsTo
    {
        return $this->belongsTo(UserModel::class(), 'reviewed_by_id');
    }
}
