<!-- This GitHub repository is a mirror: pull requests are reviewed here and merged on the
maintainer's GitLab, then mirrored back (docs/guides/releasing.md, "External pull requests"). -->

## What and why

## Checklist

- [ ] Clean-room (CONTRIBUTING.md, ADR 0001): written only from the standards; no code read,
      copied or ported from libiec61850, pyiec61850 or any other IEC 61850/MMS implementation.
- [ ] I agree to license this contribution under Apache-2.0.
- [ ] Tests added or updated; `ctest` and `pytest` pass locally.
- [ ] Public API changes are mirrored in the Python binding, and CHANGELOG.md has an entry under
      `[Unreleased]`.
