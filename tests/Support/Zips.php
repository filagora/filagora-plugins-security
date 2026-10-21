<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Tests\Support;

use Illuminate\Http\UploadedFile;
use ZipArchive;

final class Zips
{
    /**
     * A real ZIP upload holding the given entries (name => contents).
     *
     * @param  array<string, string>  $entries
     */
    public static function make(array $entries = ['widget/readme.txt' => 'hello'], string $name = 'widget.zip'): UploadedFile
    {
        $path = tempnam(sys_get_temp_dir(), 'plugin-zip-');
        $zip = new ZipArchive;
        $zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE);

        foreach ($entries as $entry => $contents) {
            $zip->addFromString($entry, $contents);
        }

        $zip->close();

        return new UploadedFile($path, $name, 'application/zip', null, true);
    }
}
