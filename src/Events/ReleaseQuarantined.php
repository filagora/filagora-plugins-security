<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Events;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A release was taken out of public view, by a scan (`$moderator` is null) or by a moderator.
 * `$tellAuthors` is false when something else already tells them, such as the scan-complete email
 * for an upload.
 */
final class ReleaseQuarantined
{
    use Dispatchable;

    public function __construct(
        public readonly PluginRelease $release,
        public readonly ?SecurityScan $scan,
        public readonly ?Authenticatable $moderator,
        public readonly bool $tellAuthors,
    ) {}
}
