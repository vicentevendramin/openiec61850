# Criteria of the 0.1.0 alpha release

"Ready" became a verifiable goal: `0.1.0` is a public Alpha release on PyPI and GitHub, with an unstable API and no claim of conformance. A tag requires green GitLab CI, a green libiec61850 interop suite in both directions, built Linux x86_64 and aarch64 wheels and the maintainer's explicit confirmation, because a version published to PyPI cannot be republished.

Two points are waived on purpose. IEC61850bean, required by ADR 0007, does not block the alpha: requiring only libiec61850 gives independent validation in both directions without delaying the first release. TLS is validated against `openssl` as an independent peer, since the libiec61850 suite does not cover it.

## Consequences

- The CHANGELOG lists what was not verified: passages written without the text of the standard, such as the ObtainFile encoding, the `(n)` form in DataRef and the IEC 62351-3 cipher suites, and the lack of TLS interop with another IEC 61850 implementation.
- GOOSE/SV signing (IEC 62351-6) and certificate authentication in ACSE (IEC 62351-4) are left out, as known limitations.
- macOS and Windows do not block the release.
- Without the Reference benchmark, no project material promises performance until `1.0`.
