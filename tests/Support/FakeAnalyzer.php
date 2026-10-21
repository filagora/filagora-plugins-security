<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Support;

use Closure;
use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanContext;
use Filagora\PluginsSecurity\Contracts\ReleaseAnalyzer;

/**
 * An analyzer whose outcome the test decides.
 */
final class FakeAnalyzer implements ReleaseAnalyzer
{
    public int $runs = 0;

    /**
     * @param  Closure(ScanContext): AnalyzerResult  $outcome
     */
    public function __construct(private readonly Closure $outcome, private readonly bool $available = true, private readonly string $name = 'fake') {}

    public function name(): string
    {
        return $this->name;
    }

    public function version(): string
    {
        return '9';
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function analyze(ScanContext $context): AnalyzerResult
    {
        $this->runs++;

        return ($this->outcome)($context);
    }
}
