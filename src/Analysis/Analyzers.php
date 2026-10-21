<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis;

use Filagora\PluginsSecurity\Contracts\ReleaseAnalyzer;

/**
 * The analyzers every standard scan runs, in order. The package registers its own; a host or a
 * profile package adds more with `register()`. The AI review is not among them: it runs only on request.
 */
final class Analyzers
{
    /** @var list<ReleaseAnalyzer> */
    private array $analyzers = [];

    public function register(ReleaseAnalyzer $analyzer): void
    {
        $this->analyzers[] = $analyzer;
    }

    /**
     * @return list<ReleaseAnalyzer>
     */
    public function all(): array
    {
        return $this->analyzers;
    }
}
