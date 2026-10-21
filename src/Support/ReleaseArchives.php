<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\Plugins\Models\PluginRelease;
use Illuminate\Support\Facades\Storage;
use RuntimeException;

/**
 * Puts a stored release archive on local disk, which the extractor and the scanning tools need.
 */
final class ReleaseArchives
{
    /**
     * The archive as a local file, and a closure that removes the copy when there is one.
     *
     * @return array{path: string, cleanup: \Closure(): void}
     */
    public function local(PluginRelease $release): array
    {
        $name = (string) config('filagora-plugins.storage.disk');
        $path = (string) $release->zip_path;
        $disk = Storage::disk($name);

        if ($path === '' || ! $disk->exists($path)) {
            throw new RuntimeException('The release archive was not found.');
        }

        if (config("filesystems.disks.{$name}.driver") === 'local') {
            return ['path' => $disk->path($path), 'cleanup' => static function (): void {}];
        }

        $temporary = tempnam(sys_get_temp_dir(), 'filagora-archive-');
        $stream = $disk->readStream($path);

        if ($temporary === false || $stream === null) {
            throw new RuntimeException('The release archive could not be read.');
        }

        try {
            $target = fopen($temporary, 'wb');

            if ($target === false) {
                throw new RuntimeException('The release archive could not be copied.');
            }

            stream_copy_to_stream($stream, $target);
            fclose($target);
        } finally {
            fclose($stream);
        }

        return ['path' => $temporary, 'cleanup' => static function () use ($temporary): void {
            @unlink($temporary);
        }];
    }
}
