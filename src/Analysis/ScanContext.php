<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis;

use Filagora\Plugins\Models\PluginRelease;
use Generator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Everything an analyzer needs for one scan: the release, the archive on local disk, and its
 * contents extracted into a private temporary directory.
 */
final readonly class ScanContext
{
    public function __construct(
        public PluginRelease $release,
        public string $extractedPath,
        public string $archivePath,
    ) {}

    /**
     * Every regular file under the extracted directory.
     *
     * @return Generator<int, SplFileInfo>
     */
    public function files(): Generator
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->extractedPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY,
        );

        foreach ($iterator as $file) {
            if ($file instanceof SplFileInfo && $file->isFile()) {
                yield $file;
            }
        }
    }

    public function relativePath(SplFileInfo $file): string
    {
        return ltrim(str_replace('\\', '/', substr($file->getPathname(), strlen($this->extractedPath))), '/');
    }
}
