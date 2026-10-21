<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Enums;

enum ScanKind: string
{
    /** The automated pipeline (static PHP, ClamAV, Semgrep) that drives quarantine. */
    case STANDARD = 'standard';

    /** A staff-requested, advisory review by a language model. It never quarantines. */
    case LLM = 'llm';

    public function label(): string
    {
        return match ($this) {
            self::STANDARD => 'Standard',
            self::LLM => 'AI review',
        };
    }
}
