<?php

declare(strict_types=1);

return [
    'a_moderator' => 'a moderator',
    'truncated' => ':omitted further finding(s) omitted: the result is capped at :limit.',
    'job_failed' => 'The scan job failed: :message',

    'refusals' => [
        'not_permitted' => 'You are not allowed to do that.',
        'note_required' => 'Please give a reason.',
        'already_quarantined' => 'This release is already quarantined.',
        'not_quarantinable' => 'Only a live or waiting release can be quarantined.',
        'not_quarantined' => 'This release is not quarantined.',
        'unknown_finding' => 'That finding is not in this scan.',
    ],

    'notes' => [
        'release' => 'Release :version',
        'auto_quarantined' => 'Quarantined automatically by security scan #:scan: :severity finding.',
        'auto_cleared' => 'Cleared automatically: a re-scan by scanner v:version found no issues.',
        'quarantined_by' => 'Quarantined by :name: :note',
        'cleared_by' => 'Quarantine cleared by :name: :note',
    ],

    'llm' => [
        'not_configured' => 'The AI review is not configured.',
        'failed' => 'The AI review failed.',
        'job_failed' => 'The AI review job failed: :message',
    ],

    'guard' => [
        'reason' => 'The latest scan has a finding of :severity or worse that nobody has accepted.',
    ],
];
