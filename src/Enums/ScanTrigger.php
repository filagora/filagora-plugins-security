<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Enums;

enum ScanTrigger: string
{
    /** The scan queued when a release is uploaded. */
    case UPLOAD = 'upload';

    /** A moderator asked for a scan of one release. */
    case MANUAL = 'manual';

    /** A bulk re-scan after the scanner version was raised. */
    case BACKFILL = 'backfill';

    /** The scheduled sweep that re-scans releases left stale by a version bump. */
    case SWEEP = 'sweep';

    /** A re-scan started from the command line. */
    case RESCAN = 'rescan';

    public function label(): string
    {
        return match ($this) {
            self::UPLOAD => 'Upload',
            self::MANUAL => 'Manual',
            self::BACKFILL => 'Version backfill',
            self::SWEEP => 'Scheduled sweep',
            self::RESCAN => 'Re-scan',
        };
    }

    /**
     * Whether the uploader and owner get the "scan complete" email. Only the scan of a new upload
     * does: every other scan is read on the dashboard.
     */
    public function emailsAuthorTheResult(): bool
    {
        return $this === self::UPLOAD;
    }

    /**
     * Whether the support address is told of a serious finding. Upload only, or a re-scan or the
     * sweep would raise the same alarm for the same finding over and over.
     */
    public function emailsSupportTheFinding(): bool
    {
        return $this === self::UPLOAD;
    }

    /**
     * Whether an automatic quarantine emails the author. The scan-complete email already covers an
     * upload, and a backfill is a bulk sweep that staff read on the dashboard; a re-scan, the sweep
     * or a manual scan that pulls a live release does tell them.
     */
    public function emailsAuthorTheQuarantine(): bool
    {
        return match ($this) {
            self::MANUAL, self::RESCAN, self::SWEEP => true,
            self::UPLOAD, self::BACKFILL => false,
        };
    }
}
