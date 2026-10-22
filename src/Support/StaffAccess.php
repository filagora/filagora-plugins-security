<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\Core\Contracts\AccessChecker;

/**
 * Whether the person at the dashboard may see scans and act on them.
 */
final class StaffAccess
{
    public static function allowed(): bool
    {
        return app(AccessChecker::class)->allows(auth()->user(), Gates::key(Gates::SECURITY));
    }
}
