# Clean-room implementation under Apache-2.0

libiec61850 (MZ Automation) is GPLv3 or commercial. openiec61850 is implemented only from the text of the IEC 61850 standard (and the ISO/MMS standards it references), without reading or porting libiec61850 code, and is licensed under Apache-2.0. It can therefore be used in closed products, which is its main difference from libiec61850.

## Consequences

- Contributors cannot copy excerpts from libiec61850 or "translate" its functions.
- Running libiec61850 binaries as an interoperability test peer and in benchmarks is allowed, since that is execution, not derivation of code.
