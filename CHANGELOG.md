# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-10-22

First release.

### Added

- The scan tables (`plugin_release_security_scans`, `plugin_release_scan_finding_reviews`), their models, and the
  foreign keys from `plugin_releases` to a scan, declared as a schema extension of the plugins package.
- `Scanner`, which runs the registered analyzers over an unpacked release and records one scan; the static PHP,
  ClamAV and Semgrep analyzers; `Analyzers::register()` and the `ReleaseAnalyzer` contract for more.
- `Quarantine` (automatic, by hand, and an optional clear when a re-scan is clean) and `FindingReviews` (accept a
  finding for a plugin by its fingerprint), both gated by `filagora.plugins.security`.
- A scan queued when a release is submitted, `filagora:plugins:security-scan` (with `--prune`) and
  `filagora:plugins:security-sweep` for the host to schedule.
- The advisory AI review and the `LlmReviewer` contract the host binds.
- An archive guard that keeps a release with an unaccepted serious finding active.
- Events, and default emails that `mail.enabled` switches off.
- Staff screens on the plugin releases screen of the plugins package (needs `filagora-plugins` 0.3): the scan result
  and scanner version as columns with filters, the latest scan and AI review as modals, re-scan, AI review,
  quarantine, clear and email-the-author actions, a bulk re-scan, and the scan history on the edit page with
  accepting findings.

### Differences from the site this was extracted from

- The AI review calls a model through your `LlmReviewer`; the HTTP client and usage accounting stay with the host.
- The backtick operator is reported once per use, not once per backtick.
- A `php -l` that fails to run (a missing binary) is no longer reported as a syntax error in the file.
- Scans are read from any filesystem disk; archives on a remote disk are copied to a temporary file first.
- The backfill marker kept in a settings table is gone: `filagora:plugins:security-sweep` covers a version bump.
- Notes, audits: a quarantine leaves a staff note on the plugin; there is no audit-log entry.
- The "hold an auto-published release until its first scan" setting was only ever configuration on the site and is
  not carried over.
