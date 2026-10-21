<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Exceptions;

use Filagora\PluginsSecurity\Enums\SecurityRefusal;
use RuntimeException;

/**
 * A quarantine, clear or reviewed finding that cannot be carried out. The message is safe to show.
 */
final class SecurityRefused extends RuntimeException
{
    public function __construct(public readonly SecurityRefusal $reason, ?string $detail = null)
    {
        parent::__construct($detail ?? $reason->message());
    }
}
