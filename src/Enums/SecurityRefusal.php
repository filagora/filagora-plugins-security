<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Enums;

/**
 * Why a quarantine, a clear or a reviewed finding was refused.
 */
enum SecurityRefusal: string
{
    case NOT_PERMITTED = 'not_permitted';
    case NOTE_REQUIRED = 'note_required';
    case ALREADY_QUARANTINED = 'already_quarantined';
    case NOT_QUARANTINABLE = 'not_quarantinable';
    case NOT_QUARANTINED = 'not_quarantined';
    case UNKNOWN_FINDING = 'unknown_finding';

    public function message(): string
    {
        return __("filagora-plugins-security::messages.refusals.{$this->value}");
    }
}
