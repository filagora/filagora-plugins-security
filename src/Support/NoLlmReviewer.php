<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\PluginsSecurity\Contracts\LlmReviewer;
use LogicException;

/**
 * The default `LlmReviewer`: no model is connected, so the AI review is off.
 */
final class NoLlmReviewer implements LlmReviewer
{
    public function isConfigured(): bool
    {
        return false;
    }

    public function model(): string
    {
        return 'none';
    }

    public function complete(array $messages): string
    {
        throw new LogicException('No LlmReviewer is bound.');
    }
}
