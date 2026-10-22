# AGENTS

Guidance for AI coding agents working in `filagora-plugins-security`. `CLAUDE.md` imports this file; edit here.

## What this is

**filagora/filagora-plugins-security**: Security scanning and quarantine for `filagora-plugins`: static PHP checks, ClamAV, Semgrep and an LLM review contract.

Part of Filagora, a family of MIT-licensed Laravel 13 / Filament 5 packages (forums, CMS, entitlements, logs, compliance, messages, search, push, memberships, plugins). Composer vendor `filagora`, namespace `Filagora\<Name>\` (here `Filagora\PluginsSecurity\`), default table prefix `filagora_`, commands `filagora:*`, env `FILAGORA_*`. Every package is pre-1.0 (`0.x`): the API may change between minor versions.

Dependencies are declared in `composer.json` (`require` is hard, `suggest` is optional). Other packages must keep working when an optional one is absent; each package's `tests/Entitlements` directory proves that.

## Layout

`src/` (service provider, `FilagoraPluginsSecurityPlugin`, `Analysis/` for the extractor, the analyzers and their result types, `Services/`, `Jobs/`, `Console/`, `Events/`, `Listeners/`, `Notifications/`, `Models/`), `config/filagora-plugins-security.php`, `database/migrations` + `database/schema.php` + `database/extensions/plugins.php`, `resources/` (lang, the Semgrep rules), `tests/` (Pest, Testbench: `testbench.yaml`).

## This package

- A scan is an immutable row. `Scanner` records it, moves `latest_security_scan_id` quietly (`saveQuietly`, so the release's own hooks do not run), asks `Quarantine::evaluateAfterScan()` what it means, and dispatches `ScanFinished`. Nothing but `Scanner` writes a standard scan; the AI review (`LlmReviews`) is a separate `kind = llm` row that never becomes the latest scan and never decides a quarantine.
- Quarantine sets `PluginStatus::QUARANTINED` and remembers the status it came from; lifting it restores that. Findings a moderator accepted (by fingerprint, per plugin) do not count toward it: always ask `AcceptedFindings::effectiveSeverity()`, never the scan's own severity, when deciding anything about a release.
- The manual actions (`Quarantine::quarantine/clear`, `FindingReviews::accept/revoke`) check `filagora.plugins.security` themselves and want a note; the automatic path checks nobody.
- Services take the `AccessChecker` in their constructors and are singletons, so nothing that is resolved while the service provider boots may depend on one (the host binds its checker later). `SeriousFindingGuard` therefore takes `AcceptedFindings`, which needs none.
- Analyzer output comes from arbitrary uploaded bytes: strings are scrubbed to valid UTF-8 and bounded, the stored findings are capped, and the archive is checked again (zip-slip, entry count, size) before it is extracted. Never run code from an archive.
- Everything provider-specific stays out: the AI review talks to the host's `LlmReviewer`, and the package knows no HTTP client or model. The plugin type to review for is `analyzers.llm.subject`.
- The `securityScans`, `latestSecurityScan`, `quarantineScan` and `latestLlmReview` relations are added to the configured release model in the service provider (`resolveRelationUsing`); `phpstan.neon.dist` ignores Larastan not seeing them.
- The screens add themselves to the plugins package's release screens through `ReleaseScreens` (in `FilagoraPluginsSecurityPlugin::register()`, keyed so a second panel adds nothing). Every column, filter and action is gated by `StaffAccess::allowed()`, and the services check the key again; a refusal can only happen in a race, and is shown as a notice. Filament's test helpers do not render an action modal's content: ask the component for `getMountedActionSchema()` (see `ScreensTest`).
- The scan tables match the live definitions of the site the package was extracted from, so an existing site can adopt them with `filagora:adopt`; the foreign keys on `plugin_releases` are a schema extension of the plugins package.

## Commands

Run everything through DDEV from this directory (`ddev start` once; the `testing` database is created on the first `ddev restart`).

```bash
ddev composer install
ddev composer test      # Pest, on a real MariaDB
ddev composer lint      # Pint
ddev composer analyse   # Larastan (level 6)
```

Tests always run against MariaDB (database `testing`, forced in `phpunit.xml.dist`), never SQLite, so FULLTEXT, `ONLY_FULL_GROUP_BY` and collation behave like production. Do not weaken that to make a test pass. If a port is taken, `ddev poweroff` before starting another project's DDEV.

## Conventions

- PHP 8.4, `declare(strict_types=1)` in every source file (`tests/ArchTest.php` enforces it, plus no debug calls and no `env()` outside `config/`).
- Table names always go through core's `Tables::name('x')` (prefix-aware); user foreign keys through `UserKey`/`UserModel`. Never hard-code `filagora_` or `users`.
- Config holds no closures and is merged with the host's copy, so list only what differs. Env vars are `FILAGORA_`-prefixed.
- Authorization is one question, "may this user do this?", answered by core's `AccessChecker` from the package's `gates` config. Do not call a roles or permissions package directly.
- Extend through documented contracts, events and registries. Anything undocumented is `@internal`; public API follows SemVer.
- Migrations are mirrored by a snapshot in `database/schema.php` (`filagora:schema:dump`). A table change means updating the migration, the snapshot and the adoption check together, because `filagora:adopt` compares live tables against the snapshot.

## Definition of done

- Every behaviour change ships with tests; every bug fix with a regression test that fails before the fix.
- README and `CHANGELOG.md` (`[Unreleased]`) are updated in the same change.
- `composer test`, `composer lint` and `composer analyse` pass.
- Work on a branch and open a pull request (`gh pr merge --squash --delete-branch`). `master` is protected and squash-only.
- Confirm with the user before tagging a release, creating or deleting repositories or branches, or anything else outward-facing. Tags create the GitHub release from the matching `CHANGELOG.md` section; the user submits new packages to Packagist.

## Public repository: keep private details out

This repository is public and CI runs a leak scan (private patterns, any IPv4 literal, any email address not on a reserved test domain, gitleaks). Never write real hostnames, IP addresses, personal emails, the name of the site the packages were extracted from, or plan/infrastructure details into code, docs, fixtures, commit messages or PRs. Use `example.test`-style addresses.

## CI

`.github/workflows/ci.yml` calls the reusable workflows in `filagora/filagora-shared` at `@master` (tests, lint, leak scan, release). Fix CI problems there, not by copying logic into this repo.
