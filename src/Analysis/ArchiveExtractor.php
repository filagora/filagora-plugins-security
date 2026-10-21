<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis;

use RuntimeException;
use ZipArchive;

/**
 * Extracts a stored archive into a fresh private temporary directory. A stored archive is trusted
 * no more than a new upload, so the path and size limits are checked again before anything is written.
 */
class ArchiveExtractor
{
    /**
     * @return array{path: string, cleanup: \Closure(): void}
     */
    public function extract(string $archivePath): array
    {
        if (! is_file($archivePath)) {
            throw new RuntimeException('The release archive was not found.');
        }

        $zip = new ZipArchive;

        if ($zip->open($archivePath, ZipArchive::RDONLY) !== true) {
            throw new RuntimeException('The release archive could not be opened.');
        }

        $maxEntries = (int) config('filagora-plugins.archive.max_entries', 5000);
        $maxBytes = (int) config('filagora-plugins.archive.max_uncompressed_bytes', 200 * 1024 * 1024);

        try {
            if ($zip->numFiles > $maxEntries) {
                throw new RuntimeException("The release archive has too many entries ({$zip->numFiles}).");
            }

            $total = 0;

            for ($i = 0; $i < $zip->numFiles; $i++) {
                $name = (string) $zip->getNameIndex($i);

                if ($name !== '' && $this->escapes($name)) {
                    throw new RuntimeException("The release archive contains an unsafe path: {$name}");
                }

                $stat = $zip->statIndex($i);
                $total += is_array($stat) ? (int) $stat['size'] : 0;

                if ($total > $maxBytes) {
                    throw new RuntimeException('The release archive is too large once unpacked.');
                }
            }

            $directory = $this->makeDirectory();

            if ($zip->extractTo($directory) !== true) {
                $this->remove($directory);

                throw new RuntimeException('The release archive could not be extracted.');
            }

            return [
                'path' => $directory,
                'cleanup' => fn () => $this->remove($directory),
            ];
        } finally {
            $zip->close();
        }
    }

    private function makeDirectory(): string
    {
        $directory = sys_get_temp_dir().'/filagora-scan-'.bin2hex(random_bytes(8));

        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('A directory to scan in could not be created.');
        }

        return $directory;
    }

    private function remove(string $directory): void
    {
        if (! is_dir($directory)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }

        @rmdir($directory);
    }

    private function escapes(string $entry): bool
    {
        $normalized = str_replace('\\', '/', $entry);

        if (str_starts_with($normalized, '/') || preg_match('/^[a-zA-Z]:/', $normalized) === 1) {
            return true;
        }

        return in_array('..', explode('/', $normalized), true);
    }
}
