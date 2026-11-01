# Interoperability validated without physical IEDs

The project has no access to physical IEDs. CI validates interoperability against two independent implementations running in the homelab: the libiec61850 example servers, run as binaries (which ADR 0001 allows), and the IEC61850bean server. Commercial simulators on trial licences and public pcap captures of real MMS traffic complement this validation: simulators are used in manual tests and captures become a regression and fuzzing corpus.

## Consequences

Non-conforming behaviour of specific vendors, common in Ed.1 servers, will only show up in the field. This risk is accepted, and field reports must become cases in the regression corpus.
