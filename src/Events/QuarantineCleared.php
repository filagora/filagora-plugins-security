<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Events;

use Filagora\Plugins\Models\PluginRelease;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A quarantine was lifted and the release has the status it had before. `$moderator` is null when
 * a clean re-scan lifted it.
 */
final class QuarantineCleared
{
    use Dispatchable;

    public function __construct(
        public readonly PluginRelease $release,
        public readonly ?Authenticatable $moderator,
    ) {}
}
