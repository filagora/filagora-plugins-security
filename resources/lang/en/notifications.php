<?php

declare(strict_types=1);

return [
    'scan_complete' => [
        'subject' => 'Security scan finished: :plugin v:version',
        'intro' => 'The automatic security scan of :plugin v:version has finished.',
        'action' => 'View the plugin',
        'outcome_failed' => 'The scan could not be completed. A moderator will look into it.',
        'outcome_quarantined' => 'The scan reported a :severity finding, so the release has been held back for review.',
        'outcome_flagged' => 'The scan reported :count finding(s), the worst of them :severity. A moderator may look at them.',
        'outcome_clear' => 'The scan found no problems.',
        'status_held' => 'The release is not public while it is held.',
        'status_live' => 'The release is live.',
        'status_pending' => 'The release is waiting for a moderator to approve it.',
    ],
    'quarantined' => [
        'subject' => 'Security hold on :plugin v:version',
        'intro' => 'Release v:version of :plugin has been taken out of public view because an automated security scan reported a serious finding. A moderator will review it. If it is a false positive it will be cleared; otherwise a moderator will contact you.',
        'action' => 'View the plugin',
        'reference' => 'Scan reference: #:scan (scanner v:version).',
    ],
    'quarantine_cleared' => [
        'subject' => 'Security hold lifted on :plugin v:version',
        'intro' => 'Release v:version of :plugin has passed review and is public again.',
        'action' => 'View the plugin',
    ],
    'finding_flagged' => [
        'subject' => '[Security] :plugin v:version: :severity finding',
        'intro' => 'The scan of :plugin v:version found something serious (:severity).',
        'action' => 'Review the release',
        'counts' => 'Findings: :counts',
        'held' => 'The release has been quarantined and is hidden until it is cleared.',
        'public' => 'The release remains public. Review it, and quarantine it by hand if needed.',
    ],
    'review_finished' => [
        'subject' => '[AI review] :plugin v:version: finished',
        'intro' => 'Your AI review of :plugin v:version has finished. The worst finding is :severity. The review is advisory and does not affect the standard scan or a quarantine.',
        'action' => 'Open the release',
        'counts' => 'Findings: :counts',
    ],
    'review_failed' => [
        'subject' => '[AI review] :plugin v:version: failed',
        'intro' => 'Your AI review of :plugin v:version could not be completed. Reason: :error',
        'action' => 'Open the release',
    ],
];
