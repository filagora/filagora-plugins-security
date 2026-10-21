# Contributing

Thanks for helping. `master` is protected: open a pull request, and it is
squash-merged once CI is green.

## Local setup

```bash
composer install
composer test      # Pest
composer lint      # Pint
composer analyse   # Larastan
```

## Expectations

- Every behaviour change ships with tests, and every bug fix with a regression
  test that fails before the fix.
- `env()` is used only in config files, and config holds no closures.
- Public API (documented contracts, config keys, events, registries) follows
  SemVer; everything else is `@internal`.
- Do not add private hostnames, IP addresses or personal email addresses to code,
  docs or test fixtures. CI runs a leak scan.
