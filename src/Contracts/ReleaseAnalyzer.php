<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Contracts;

use Filagora\PluginsSecurity\Analysis\AnalyzerResult;
use Filagora\PluginsSecurity\Analysis\ScanContext;

/**
 * One check run against the extracted archive of a release. An implementation must never run code
 * from the archive and must be safe to run again. Register one with `Analyzers::register()`.
 */
interface ReleaseAnalyzer
{
    /**
     * A stable machine name: the key in a scan's `analyzer_versions` and the `analyzer` of each
     * finding it makes.
     */
    public function name(): string;

    /**
     * The version of the rules, signature database or binary, recorded with every scan.
     */
    public function version(): string;

    /**
     * False when the analyzer is off or what it needs (a binary, a daemon) is missing. An
     * unavailable analyzer is recorded as skipped; it never fails the scan.
     */
    public function isAvailable(): bool;

    public function analyze(ScanContext $context): AnalyzerResult;
}
