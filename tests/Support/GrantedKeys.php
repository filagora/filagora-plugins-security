<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Support;

use Filagora\Core\Contracts\AccessChecker;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * An access checker for tests: a person is allowed the keys they were given with `give()`.
 */
final class GrantedKeys implements AccessChecker
{
    /** @var array<int|string, list<string>> */
    private array $granted = [];

    public function give(Authenticatable $user, string ...$keys): void
    {
        $this->granted[$user->getAuthIdentifier()] = $keys;
    }

    public function allows(?Authenticatable $user, string $key): bool
    {
        return $user !== null && in_array($key, $this->granted[$user->getAuthIdentifier()] ?? [], true);
    }

    public function allowsAny(?Authenticatable $user, array $keys): bool
    {
        return array_any($keys, fn (string $key): bool => $this->allows($user, $key));
    }

    public function allowsAll(?Authenticatable $user, array $keys): bool
    {
        return array_all($keys, fn (string $key): bool => $this->allows($user, $key));
    }
}
