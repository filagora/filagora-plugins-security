<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Enums;

enum ScanSeverity: string
{
    case NONE = 'none';
    case INFO = 'info';
    case LOW = 'low';
    case MEDIUM = 'medium';
    case HIGH = 'high';
    case CRITICAL = 'critical';

    public function rank(): int
    {
        return match ($this) {
            self::NONE => 0,
            self::INFO => 1,
            self::LOW => 2,
            self::MEDIUM => 3,
            self::HIGH => 4,
            self::CRITICAL => 5,
        };
    }

    public function isAtLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    /**
     * The worst of the severities; `NONE` when there are none, or none that mean anything.
     *
     * @param  iterable<self|string|null>  $severities
     */
    public static function highest(iterable $severities): self
    {
        $highest = self::NONE;

        foreach ($severities as $severity) {
            $candidate = $severity instanceof self ? $severity : self::tryFrom((string) $severity);

            if ($candidate instanceof self && $candidate->rank() > $highest->rank()) {
                $highest = $candidate;
            }
        }

        return $highest;
    }

    public function label(): string
    {
        return match ($this) {
            self::NONE => 'No findings',
            self::INFO => 'Info',
            self::LOW => 'Low',
            self::MEDIUM => 'Medium',
            self::HIGH => 'High',
            self::CRITICAL => 'Critical',
        };
    }

    public function color(): string
    {
        return match ($this) {
            self::NONE => 'success',
            self::INFO, self::LOW => 'gray',
            self::MEDIUM => 'warning',
            self::HIGH, self::CRITICAL => 'danger',
        };
    }
}
