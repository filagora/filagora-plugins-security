<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Services;

use Filagora\Core\Contracts\AccessChecker;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\SecurityRefusal;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\Models\FindingReview;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Support\Gates;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A moderator marks a finding "reviewed, acceptable" for a plugin. The finding's fingerprint is
 * kept, so it stops counting toward quarantine in this and every later scan of the plugin.
 */
class FindingReviews
{
    public function __construct(private readonly AccessChecker $access) {}

    /**
     * @throws SecurityRefused
     */
    public function accept(PluginRelease $release, SecurityScan $scan, string $fingerprint, Authenticatable $moderator, ?string $note = null): FindingReview
    {
        if (! $this->access->allows($moderator, Gates::key(Gates::SECURITY))) {
            throw new SecurityRefused(SecurityRefusal::NOT_PERMITTED);
        }

        $known = $scan->plugin_release_id === $release->getKey()
            && collect($scan->findings ?? [])->contains(fn (array $finding): bool => ($finding['fingerprint'] ?? null) === $fingerprint);

        if (! $known) {
            throw new SecurityRefused(SecurityRefusal::UNKNOWN_FINDING);
        }

        return FindingReview::query()->updateOrCreate(
            ['plugin_id' => $release->plugin_id, 'fingerprint' => $fingerprint],
            ['reviewed_by_id' => $moderator->getAuthIdentifier(), 'note' => $note !== null && trim($note) !== '' ? trim($note) : null],
        );
    }

    /**
     * Take the acceptance back; the finding counts again from the next scan.
     *
     * @throws SecurityRefused
     */
    public function revoke(PluginRelease $release, string $fingerprint, Authenticatable $moderator): void
    {
        if (! $this->access->allows($moderator, Gates::key(Gates::SECURITY))) {
            throw new SecurityRefused(SecurityRefusal::NOT_PERMITTED);
        }

        FindingReview::query()->where('plugin_id', $release->plugin_id)->where('fingerprint', $fingerprint)->delete();
    }
}
