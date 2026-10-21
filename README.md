# Filagora Plugins Security

Security scanning and quarantine for [Filagora Plugins](https://github.com/filagora/filagora-plugins): every uploaded
release is unpacked and checked, a serious finding takes the release out of public view, and a moderator can accept a
finding, clear a quarantine or ask a language model for a second opinion.

> The package is at `0.1`: the API may change between `0.x` minor versions. It is a scanner, a quarantine service and
> staff screens; it has no public pages.

## Requirements

PHP 8.4 with `ext-zip`, Laravel 13, Filament 5, `filagora/filagora-core` and `filagora/filagora-plugins`. Tested
against MariaDB 11.4. ClamAV, Semgrep and a language model are optional and off until you set them up.

## Tables

`plugin_release_security_scans` (one row per scan) and `plugin_release_scan_finding_reviews` (findings a moderator
accepted, by fingerprint), prefixed `filagora_` by default, plus the two foreign keys from `plugin_releases` to a
scan (`latest_security_scan_id`, `quarantine_scan_id`), which the plugins package ships as plain columns. A site
that already has these tables can adopt them with `php artisan filagora:adopt`.

## How a scan works

When a release is submitted (`ReleaseSubmitted` from the plugins package), a `ScanReleaseJob` is queued. It unpacks
the archive into a private temporary directory (checking the paths and sizes again), runs each analyzer, and records
one scan with every finding, the version of each analyzer and the scanner, and the worst severity. It then decides
what that means for the release:

- A finding at or above `scanner.quarantine_threshold` (default `critical`) **quarantines** the release: its status
  becomes `quarantined`, which every list, search, download and feed already treats as not public, the status it had
  is remembered, and a note says why. Findings a moderator has accepted for that plugin do not count.
- A serious finding (high or worse) in a new upload tells the support address.
- With `scanner.auto_clear_when_clean`, a clean re-scan lifts the quarantine.
- The uploader and the owner get one email, when the scan of the upload ends. Later scans are read on the dashboard.

| Analyzer | Needs | What it looks for |
| --- | --- | --- |
| `static_php` | nothing | `php -l` syntax errors, dangerous calls found with the tokenizer (so a word in a comment does not count), the backtick operator, obfuscated payloads, `preg_replace` with `/e`, PHAR archives, PHP handlers in `.htaccess`, PHP files that start like an image, files on your known-bad hash list |
| `clamav` | `clamdscan` or `clamscan` | any signature match, always critical |
| `semgrep` | `semgrep` | the rules in `resources/semgrep`, or your own (`ruleset_path`) |

Each is switched on or off in `config/filagora-plugins-security.php`; one that is off, or whose binary is missing, is
recorded as skipped and never fails the scan. Add your own with `Analyzers::register()` and the `ReleaseAnalyzer`
contract (it must never run code from the archive).

## Keeping scans current

Raise `scanner.version` whenever the analyzers or their rules change. A release whose latest scan used an older
version is stale. Schedule the sweep to re-scan a few at a time, so a version bump does not drop dozens of
minutes-long scans at once:

```php
Schedule::command('filagora:plugins:security-sweep')->everyThirtyMinutes();
```

`filagora:plugins:security-scan` scans by hand (`--release`, `--plugin`, `--status`, `--never-scanned`, `--stale`,
`--sync`, `--dry-run`), and `--prune` deletes redundant scan history, keeping the latest scan, the one behind a
quarantine and the newest of each scanner version. Give the jobs a queue of their own with `scanner.queue`.

## Quarantine and accepted findings

```php
$quarantine = app(\Filagora\PluginsSecurity\Services\Quarantine::class);
$quarantine->quarantine($release, $moderator, 'Phones home to an unknown server');
$quarantine->clear($release, $moderator, 'Checked by hand: it is the update check');

app(\Filagora\PluginsSecurity\Services\FindingReviews::class)->accept($release, $scan, $fingerprint, $moderator, 'Used by the installer');
```

Both need the `filagora.plugins.security` key from the access checker (remap it in `gates`), want a reason, and throw
`SecurityRefused` with a reason and a message that is safe to show. A finding's fingerprint is the same on every scan
of the same code, so accepting it once stops it counting for that plugin from then on.

A release whose latest scan still holds a finding at or above `archive.keep_at_severity` (default `high`) that nobody
has accepted is kept active when old releases are archived.

## AI review

An advisory review by a language model, run only when staff ask for it (it costs money). The package builds the
prompts, batches the source, treats the plugin's code as data, drops findings that name a file or quote code that is
not there, flags text aimed at manipulating a reviewer, and caps every finding below critical: it can flag a release
for a moderator but never quarantines one. It knows no provider. Bind your own `LlmReviewer`:

```php
$this->app->bind(\Filagora\PluginsSecurity\Contracts\LlmReviewer::class, MyReviewer::class);
```

`complete()` takes the messages and returns the model's text; keep timeouts, retries and usage accounting in your
implementation. Then set `analyzers.llm.enabled`. A review is a scan of kind `llm`: it never becomes the release's
latest scan, and only the person who asked is emailed.

## Events and mail

`ScanFinished`, `ReleaseQuarantined` (with whether to tell the authors), `QuarantineCleared`, `SeriousFindingFlagged`
(uploads only) and `LlmReviewFinished`. The default emails read their words from
`resources/lang/en/notifications.php`; set `mail.enabled` to false to send your own from the events.

## Testing

```bash
composer test
```
