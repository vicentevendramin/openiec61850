# openiec61850

Clean-room library of the IEC 61850 standard with a native core and a first-class Python API.

## Language

### Project

**Binding parity**:
The guarantee that every public feature of the native core also exists in the Python API, with nothing exclusive to the native side.
_Avoid_: "100% compatibility", pybind compatibility

**pyiec61850 compatibility layer**:
A separate, optional package that imitates the API of libiec61850's SWIG binding to migrate legacy code; it is not part of the core.
_Avoid_: compatible mode, drop-in

**Reference benchmark**:
A comparative measurement between openiec61850 and libiec61850 on the same machine, which serves as the official criterion for "high performance".
_Avoid_: performance test (generic)

**Alpha release**:
A public 0.x version published after meeting the release criteria, with an unstable API and no claim of conformance to the standard.
_Avoid_: ready, stable, certified

### Communication roles

**Client**:
ACSI role that establishes an association with a Server through MMS over the ISO/TCP stack and invokes services on it.
_Avoid_: master, subscriber

**Server**:
ACSI role performed by an IED that exposes its data model and serves the requests of Clients through MMS.
_Avoid_: slave, publisher

**Subscriber**:
Role that receives layer 2 multicast messages (GOOSE or SV) from a Publisher, without an association.
_Avoid_: GOOSE client, MMS subscriber

**Publisher**:
Role that sends GOOSE or SV multicast messages.
_Avoid_: GOOSE server

**Association**:
Logical session established between a Client and a Server, within which services are invoked.
_Avoid_: connection (when speaking at the ACSI level)

**ACSI layer**:
API level that speaks in IEC 61850 terms (Association, LD/LN/DO/DA, RCB, control, setting groups and so on).
_Avoid_: high-level API

**Generic MMS layer**:
API level that speaks in ISO 9506 terms (domains, named variables, GetNameList, Read/Write), without IEC 61850 semantics; it is public for diagnostics and for non-conforming Servers.
_Avoid_: low-level API, raw MMS

### Data model in the Client

**MMS value**:
Generic representation, without model type, of a data item carried over MMS (structure, array, integer, float, bit-string, UtcTime and so on).
_Avoid_: MmsValue (the libiec61850 name)

**Discovered model**:
Navigable tree of a Server's data model (LD/LN/DO/DA), built at run time through the directory and definition services.
_Avoid_: dynamic model, cache

**SCL model**:
A Server's data model obtained offline from an SCL file (ICD/CID/SCD), instead of online discovery.
_Avoid_: static model

**Quality**:
Quality attribute associated with a data item (validity, source, test, operator blocked and so on), per IEC 61850-7-3.
_Avoid_: status, flags

**Timestamp**:
IEC 61850 UtcTime instant with a fraction of a second and time quality (accuracy, leap second, synchronisation).
_Avoid_: datetime, time

### Reporting

**RCB**:
Report control block in the Server that defines what is reported to the Client and how; it can be buffered (BRCB) or unbuffered (URCB).
_Avoid_: subscription, report subscription

**Report**:
Unsolicited message that the Server sends to the Client when an enabled RCB is triggered.
_Avoid_: event, notification

**EntryID**:
Identifier of an entry in a BRCB's buffer, used to resume the flow of reports without loss after an interruption.
_Avoid_: sequence number (SqNum is something else)

**Association recovery**:
Automatic and optional recovery of a lost Association: reconnection and re-enabling of the RCBs, resuming BRCBs from the last EntryID received.
_Avoid_: auto-reconnect (which suggests only a TCP reconnection)

**Server edition**:
Edition of IEC 61850 (Ed.1, Ed.2 or Ed.2.1) that the Server implements, which changes the semantics of some services and control blocks.
_Avoid_: version
