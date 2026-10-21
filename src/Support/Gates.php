<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

/**
 * The access key behind the package's ability, as set in `filagora-plugins-security.gates`
 * (`ability => key`). A host remaps the key there; the ability keeps its name.
 */
final class Gates
{
    public const SECURITY = 'filagora.plugins.security';

    public static function key(string $ability): string
    {
        $key = ((array) config('filagora-plugins-security.gates', []))[$ability] ?? null;

        return is_string($key) && $key !== '' ? $key : $ability;
    }
}
