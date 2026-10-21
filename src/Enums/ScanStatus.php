<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Enums;

enum ScanStatus: string
{
    case PENDING = 'pending';
    case RUNNING = 'running';
    case COMPLETED = 'completed';
    case FAILED = 'failed';
    case SKIPPED = 'skipped';

    public function label(): string
    {
        return match ($this) {
            self::PENDING => 'Pending',
            self::RUNNING => 'Running',
            self::COMPLETED => 'Completed',
            self::FAILED => 'Failed',
            self::SKIPPED => 'Skipped',
        };
    }

    public function color(): string
    {
        return match ($this) {
            self::PENDING, self::RUNNING => 'gray',
            self::COMPLETED => 'success',
            self::FAILED => 'danger',
            self::SKIPPED => 'warning',
        };
    }

    public function isFinished(): bool
    {
        return match ($this) {
            self::COMPLETED, self::FAILED, self::SKIPPED => true,
            self::PENDING, self::RUNNING => false,
        };
    }
}
