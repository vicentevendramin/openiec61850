"""The asyncio ACSI client."""

from __future__ import annotations

import asyncio
import collections
import enum
import inspect
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import IO, Any, Generic, TypeVar, Union

from openiec61850 import _core
from openiec61850._control import Control, Originator, _options
from openiec61850._errors import ConnectionClosed, Iec61850Error, InvalidReference
from openiec61850._types import (
    FC,
    BasicType,
    CtlModel,
    Edition,
    EntryID,
    EntryTime,
    MmsType,
    ObjectClass,
    ObjectReference,
    OptFlds,
    Timestamp,
    TrgOps,
)
from openiec61850._values import TypeNeeded, TypeSpec, decode, encode, spec_from_definition, spec_from_tagged

__all__ = [
    "Client",
    "Recovery",
    "IsoParameters",
    "ConnectionState",
    "EventKind",
    "ConnectionEvent",
    "EventStream",
    "AssociationInfo",
    "NegotiatedParameters",
    "LogicalNodeDirectory",
    "DataDirectoryEntry",
    "DataDefinition",
    "DefinitionKind",
    "DataSetDirectory",
    "RcbValues",
    "RcbSettings",
    "Report",
    "ReportEntry",
    "ReportSubscription",
    "ReportStream",
    "SgcbValues",
    "LcbValues",
    "LcbSettings",
    "LogEntry",
    "LogEntryData",
    "FileEntry",
    "GoCBValues",
    "GoCBSettings",
    "GooseAddress",
    "DEFAULT_AP_TITLE",
    "DEFAULT_AE_QUALIFIER",
]

Ref = Union[str, ObjectReference]
T = TypeVar("T")

DEFAULT_AP_TITLE = "1.1.999.1"
DEFAULT_AE_QUALIFIER = 12


def _ref_text(r: Ref) -> str:
    return str(r)


def _ref(text: str | None, edition: Edition) -> ObjectReference | None:
    if text is None:
        return None
    return ObjectReference(text, edition=edition, strict_ln_names=False)


def _canonical(r: Ref, edition: Edition) -> str:
    if isinstance(r, ObjectReference):
        return str(r)
    return str(ObjectReference(r, edition=edition, strict_ln_names=False))


def _seconds(v: float | None) -> float | None:
    return None if v is None else float(v)


# ---------------------------------------------------------------------------------------------
# Options


@dataclass(frozen=True)
class Recovery:
    """Association recovery: reconnect, re-enable the RCBs and resume BRCBs from the last EntryID.

    ``backoff`` is the delay before each attempt in seconds (the last one repeats);
    ``max_attempts`` bounds the attempts per loss (0: unlimited).
    """

    backoff: Sequence[float] = (0.1, 0.5, 1.0, 2.0, 5.0)
    max_attempts: int = 0


@dataclass(frozen=True)
class IsoParameters:
    """ISO stack addressing and MMS Initiate proposal; ``None`` keeps the IEC 61850-8-1 default."""

    calling_tsap: bytes | None = None
    called_tsap: bytes | None = None
    calling_session_selector: bytes | None = None
    called_session_selector: bytes | None = None
    calling_presentation_selector: bytes | None = None
    called_presentation_selector: bytes | None = None
    max_tpdu_size: int | None = None
    local_detail: int | None = None
    max_serv_outstanding_calling: int | None = None
    max_serv_outstanding_called: int | None = None
    nesting_level: int | None = None
    max_nesting: int | None = None
    unconfirmed_queue_capacity: int | None = None
    keep_alive: bool | None = None
    no_delay: bool | None = None
    read_buffer_size: int | None = None
    local_reference: int | None = None
    max_tsdu_size: int | None = None
    max_tpkt_size: int | None = None
    session_versions: int | None = None  # bit 0: version 1, bit 1: version 2 (X.225)
    version_number: int | None = None
    parameter_cbb: tuple[bytes, int] | None = None  # (octets, bit count), as in NegotiatedParameters
    services_supported: tuple[bytes, int] | None = None
    # One phase each, instead of the ``timeout`` of Client.connect.
    connect_timeout: float | None = None
    handshake_timeout: float | None = None
    association_timeout: float | None = None


class ConnectionState(str, enum.Enum):
    ESTABLISHED = "established"
    RECONNECTING = "reconnecting"
    CLOSING = "closing"
    CLOSED = "closed"


class EventKind(str, enum.Enum):
    LOST = "lost"
    RECONNECTING = "reconnecting"
    RESTORED = "restored"
    FAILED = "failed"


@dataclass(frozen=True)
class ConnectionEvent:
    """A connection event: ``lost`` (``error`` says why), ``reconnecting`` (attempt number),
    ``restored`` (RCBs that could not be re-enabled in ``rcb_errors``), ``failed``."""

    kind: EventKind
    error: Iec61850Error | None = None
    attempt: int = 0
    rcb_errors: tuple[tuple[ObjectReference, Iec61850Error], ...] = ()


@dataclass(frozen=True)
class NegotiatedParameters:
    local_detail_calling: int | None
    local_detail_called: int | None
    max_serv_outstanding_calling: int
    max_serv_outstanding_called: int
    data_structure_nesting_level: int | None
    version_number: int
    parameter_cbb: tuple[bytes, int]
    services_supported_calling: tuple[bytes, int]
    services_supported_called: tuple[bytes, int]


TLS_PORT = 3782
"""IANA "secure-mms": the usual port of a TLS server."""


class TlsVersion(enum.IntEnum):
    TLS1_2 = 12
    TLS1_3 = 13


@dataclass(frozen=True)
class TlsConfig:
    """TLS (IEC 62351-3) for ``Client.connect`` and ``Server.start``.

    The defaults authenticate both sides. ``ca_file`` holds the trust anchors and
    ``certificate_file``/``private_key_file`` the local identity (PEM); a server needs an identity.
    ``crl_file`` enables revocation checks, and then needs a CRL for the issuer of the peer.
    A client checks the server certificate against ``peer_name``, or the host it connects to;
    a server checks the client name only when ``peer_name`` is set. ``verify_peer_name=False``
    keeps the chain check only. ``key_update_interval`` (seconds) and ``key_update_bytes`` renew
    the traffic keys of a TLS 1.3 session on the first write past either limit (0: no limit).
    """

    ca_file: str | os.PathLike[str] | None = None
    certificate_file: str | os.PathLike[str] | None = None
    private_key_file: str | os.PathLike[str] | None = None
    private_key_password: str | None = field(default=None, repr=False)
    crl_file: str | os.PathLike[str] | None = None
    verify_peer: bool = True
    verify_peer_name: bool = True
    peer_name: str | None = None
    min_version: TlsVersion = TlsVersion.TLS1_2
    max_version: TlsVersion | None = None
    cipher_list: str | None = None
    cipher_suites: str | None = None
    key_update_interval: int = 0
    key_update_bytes: int = 0

    def _native(self) -> dict[str, Any]:
        native: dict[str, Any] = {}
        for f in fields(self):
            v = getattr(self, f.name)
            if f.name.endswith("_file") and v is not None:
                v = os.fspath(v)
            elif f.name.endswith("_version") and v is not None:
                v = int(v)
            native[f.name] = v
        return native


@dataclass(frozen=True)
class TlsSession:
    """The outcome of the TLS handshake. The ``peer_*`` fields are empty without a peer certificate."""

    version: str
    cipher: str
    peer_subject: str
    peer_issuer: str
    peer_serial: str
    peer_fingerprint_sha256: str


@dataclass(frozen=True)
class AssociationInfo:
    negotiated: NegotiatedParameters
    peer_ap_title: str | None
    peer_ae_qualifier: int | None
    local_endpoint: tuple[str, int]
    remote_endpoint: tuple[str, int]
    tls: TlsSession | None = None


# ---------------------------------------------------------------------------------------------
# Directory and definition


@dataclass(frozen=True)
class LogicalNodeDirectory:
    """GetLogicalNodeDirectory for every ACSI class."""

    data_objects: tuple[str, ...] = ()
    data_sets: tuple[str, ...] = ()
    brcbs: tuple[str, ...] = ()
    urcbs: tuple[str, ...] = ()
    lcbs: tuple[str, ...] = ()
    gocbs: tuple[str, ...] = ()
    msvcbs: tuple[str, ...] = ()
    usvcbs: tuple[str, ...] = ()
    sgcb: bool = False


@dataclass(frozen=True)
class DataDirectoryEntry:
    name: str
    fcs: tuple[FC, ...]


class DefinitionKind(str, enum.Enum):
    STRUCTURE = "structure"
    ARRAY = "array"
    BASIC = "basic"


@dataclass(frozen=True)
class DataDefinition:
    """GetDataDefinition: a tree mirroring the MMS TypeDescription."""

    name: str
    fc: FC | None
    kind: DefinitionKind
    mms_type: MmsType
    basic_type: BasicType | None
    size: int
    variable_length: bool
    array_size: int
    children: tuple[DataDefinition, ...] = ()

    def find(self, name: str) -> DataDefinition | None:
        for c in self.children:
            if c.name == name:
                return c
        return None

    def __getitem__(self, name: str) -> DataDefinition:
        c = self.find(name)
        if c is None:
            raise KeyError(name)
        return c

    @staticmethod
    def _from(d: Mapping[str, Any]) -> DataDefinition:
        return DataDefinition(
            name=d["name"],
            fc=FC(d["fc"]) if d["fc"] is not None else None,
            kind=DefinitionKind(d["kind"]),
            mms_type=MmsType(d["mms_type"]),
            basic_type=BasicType(d["basic_type"]) if d["basic_type"] is not None else None,
            size=d["size"],
            variable_length=d["variable_length"],
            array_size=d["array_size"],
            children=tuple(DataDefinition._from(c) for c in d["children"]),
        )


@dataclass(frozen=True)
class DataSetDirectory:
    members: tuple[ObjectReference, ...]
    deletable: bool


# ---------------------------------------------------------------------------------------------
# Report control blocks


@dataclass(frozen=True)
class RcbValues:
    """Attributes of a BRCB or URCB; those the server does not have are ``None``."""

    rpt_id: str | None = None
    rpt_ena: bool | None = None
    resv: bool | None = None
    dat_set: str | None = None  # MMS form ("LD/LN$DS" or "@DS"); empty: none
    conf_rev: int | None = None
    opt_flds: OptFlds | None = None
    buf_tm: int | None = None
    sq_num: int | None = None
    trg_ops: TrgOps | None = None
    intg_pd: int | None = None
    gi: bool | None = None
    purge_buf: bool | None = None
    entry_id: EntryID | None = None
    time_of_entry: EntryTime | None = None
    resv_tms: int | None = None
    owner: bytes | None = None

    @property
    def data_set(self) -> ObjectReference | None:
        """DatSet as an object reference (None when absent, empty or not parseable)."""
        if not self.dat_set:
            return None
        try:
            return ObjectReference.from_mms_data_set(self.dat_set)
        except InvalidReference:
            return None

    @staticmethod
    def _from(d: Mapping[str, Any]) -> RcbValues:
        return RcbValues(
            rpt_id=d["rpt_id"],
            rpt_ena=d["rpt_ena"],
            resv=d["resv"],
            dat_set=d["dat_set"],
            conf_rev=d["conf_rev"],
            opt_flds=OptFlds(d["opt_flds"]) if d["opt_flds"] is not None else None,
            buf_tm=d["buf_tm"],
            sq_num=d["sq_num"],
            trg_ops=TrgOps(d["trg_ops"]) if d["trg_ops"] is not None else None,
            intg_pd=d["intg_pd"],
            gi=d["gi"],
            purge_buf=d["purge_buf"],
            entry_id=EntryID(d["entry_id"]) if d["entry_id"] is not None else None,
            time_of_entry=EntryTime(*d["time_of_entry"]) if d["time_of_entry"] is not None else None,
            resv_tms=d["resv_tms"],
            owner=d["owner"],
        )


@dataclass(frozen=True)
class RcbSettings:
    """Attributes written by :meth:`Client.set_rcb_values`; ``None`` ones are not written.

    They are written one per Write request, in this order: Resv, ResvTms, RptID, DatSet,
    OptFlds, BufTm, TrgOps, IntgPd, PurgeBuf, EntryID, RptEna, GI.
    """

    resv: bool | None = None
    resv_tms: int | None = None
    rpt_id: str | None = None
    dat_set: Ref | None = None
    opt_flds: OptFlds | int | None = None
    buf_tm: int | None = None
    trg_ops: TrgOps | int | None = None
    intg_pd: int | None = None
    purge_buf: bool | None = None
    entry_id: EntryID | bytes | None = None
    rpt_ena: bool | None = None
    gi: bool | None = None

    def _native(self) -> dict[str, Any]:
        return {
            "resv": self.resv,
            "resv_tms": self.resv_tms,
            "rpt_id": self.rpt_id,
            "dat_set": _ref_text(self.dat_set) if self.dat_set is not None else None,
            "opt_flds": int(self.opt_flds) if self.opt_flds is not None else None,
            "buf_tm": self.buf_tm,
            "trg_ops": int(self.trg_ops) if self.trg_ops is not None else None,
            "intg_pd": self.intg_pd,
            "purge_buf": self.purge_buf,
            "entry_id": bytes(self.entry_id) if self.entry_id is not None else None,
            "rpt_ena": self.rpt_ena,
            "gi": self.gi,
        }


@dataclass(frozen=True)
class ReportEntry:
    index: int  # position of the member in the data set
    data_reference: str  # MMS form as sent; empty when not included
    reference: ObjectReference | None  # the member, from data_reference or the data set directory
    value: Any
    reason: TrgOps | None


@dataclass(frozen=True)
class Report:
    """An IEC 61850 report (one segment of a segmented report)."""

    rpt_id: str
    opt_flds: OptFlds
    seq_num: int | None
    time_of_entry: EntryTime | None
    data_set: str | None  # MMS form, as sent
    buffer_overflow: bool | None
    entry_id: EntryID | None
    conf_rev: int | None
    sub_seq_num: int | None
    more_segments_follow: bool | None
    inclusion: tuple[bool, ...]
    entries: tuple[ReportEntry, ...]
    rcb: ObjectReference | None  # the RCB enabled with enable_reporting(), when matched
    lost_before: int = 0  # reports dropped immediately before this one

    def __getitem__(self, ref: Ref) -> Any:
        """The value of an included member, by reference."""
        for e in self.entries:
            if e.reference is not None and e.reference == ref:
                return e.value
        raise KeyError(str(ref))

    def values(self) -> dict[str, Any]:
        """Included values by member reference."""
        return {str(e.reference): e.value for e in self.entries if e.reference is not None}


# ---------------------------------------------------------------------------------------------
# Setting groups, logs, files and GOOSE control blocks


@dataclass(frozen=True)
class SgcbValues:
    """GetSGCBValues (IEC 61850-7-2 §16.3.6): the setting group control block of an LD."""

    num_of_sgs: int
    act_sg: int
    edit_sg: int  # 0: no group selected for editing
    cnf_edit: bool
    lact_tm: Timestamp | None = None
    resv_tms: int | None = None  # Ed.2


@dataclass(frozen=True)
class LcbValues:
    """Attributes of a log control block; those the server does not have are ``None``."""

    log_ena: bool | None = None
    log_ref: str | None = None  # MMS form "LD/LN$Log"
    dat_set: str | None = None  # MMS form "LD/LN$DS"; empty: none
    old_entr_tm: EntryTime | None = None
    new_entr_tm: EntryTime | None = None
    old_ent: EntryID | None = None
    new_ent: EntryID | None = None
    trg_ops: TrgOps | None = None
    intg_pd: int | None = None

    @property
    def data_set(self) -> ObjectReference | None:
        if not self.dat_set:
            return None
        try:
            return ObjectReference.from_mms_data_set(self.dat_set)
        except InvalidReference:
            return None


@dataclass(frozen=True)
class LcbSettings:
    """Attributes written by :meth:`Client.set_lcb_values` (one Write each, in this order:
    DatSet, TrgOps, IntgPd, LogEna); ``None`` ones are not written."""

    dat_set: Ref | None = None
    trg_ops: TrgOps | int | None = None
    intg_pd: int | None = None
    log_ena: bool | None = None

    def _native(self) -> dict[str, Any]:
        return {
            "dat_set": _ref_text(self.dat_set) if self.dat_set is not None else None,
            "trg_ops": int(self.trg_ops) if self.trg_ops is not None else None,
            "intg_pd": self.intg_pd,
            "log_ena": self.log_ena,
        }


@dataclass(frozen=True)
class LogEntryData:
    """One value of a log entry."""

    reference: str  # the MMS variable, e.g. "LD/LN$ST$Ind1$stVal"
    value: Any
    reason: TrgOps | None

    @property
    def object_reference(self) -> ObjectReference | None:
        """``reference`` as an ACSI reference (None when it cannot be parsed)."""
        try:
            return ObjectReference.from_mms(self.reference)
        except InvalidReference:
            return None


@dataclass(frozen=True)
class LogEntry:
    """A log entry (IEC 61850-7-2 §17.3.2.3, an MMS journal entry)."""

    entry_id: EntryID
    time: EntryTime
    data: tuple[LogEntryData, ...]

    def values(self) -> dict[str, Any]:
        """Values by MMS variable reference."""
        return {d.reference: d.value for d in self.data}


@dataclass(frozen=True)
class FileEntry:
    """An entry of the server's file directory."""

    name: str
    size: int
    last_modified: datetime | None


@dataclass(frozen=True)
class GooseAddress:
    """DstAddress of a GoCB."""

    mac: bytes
    priority: int
    vid: int
    app_id: int

    @property
    def mac_text(self) -> str:
        return "-".join(f"{b:02X}" for b in self.mac)


@dataclass(frozen=True)
class GoCBValues:
    """Attributes of a GOOSE control block; those the server does not have (MinTime... in Ed.1)
    are ``None``."""

    go_ena: bool | None = None
    go_id: str | None = None
    dat_set: str | None = None  # MMS form
    conf_rev: int | None = None
    nds_com: bool | None = None
    dst_address: GooseAddress | None = None
    min_time: int | None = None
    max_time: int | None = None
    fixed_offs: bool | None = None

    @property
    def data_set(self) -> ObjectReference | None:
        if not self.dat_set:
            return None
        try:
            return ObjectReference.from_mms_data_set(self.dat_set)
        except InvalidReference:
            return None


@dataclass(frozen=True)
class GoCBSettings:
    """Attributes written by :meth:`Client.set_gocb_values` (one Write each, in this order:
    GoID, DatSet, GoEna); ``None`` ones are not written."""

    go_id: str | None = None
    dat_set: Ref | None = None
    go_ena: bool | None = None

    def _native(self) -> dict[str, Any]:
        return {
            "go_id": self.go_id,
            "dat_set": _ref_text(self.dat_set) if self.dat_set is not None else None,
            "go_ena": self.go_ena,
        }


def _entry_time(t: EntryTime | datetime | None) -> tuple[int, int | None] | None:
    if t is None:
        return None
    if isinstance(t, datetime):
        t = EntryTime.from_datetime(t)
    if not isinstance(t, EntryTime):
        raise TypeError(f"expected an EntryTime or an aware datetime, got {type(t).__name__}")
    return (t.ms_of_day, t.days)


def _ts(t: tuple[Any, ...] | None) -> Timestamp | None:
    return Timestamp.from_raw(t[1], t[2], t[3]) if t is not None else None


# ---------------------------------------------------------------------------------------------
# Streams


_END = object()


class _Stream(Generic[T]):
    """A bounded queue consumed with ``async for``; the oldest item is dropped on overflow."""

    def __init__(self, maxsize: int) -> None:
        self._items: collections.deque[T] = collections.deque()
        self._maxsize = max(1, maxsize)
        self._waiter: asyncio.Future[None] | None = None
        self._ended = False
        self._error: BaseException | None = None
        self.dropped = 0

    def _put(self, item: T) -> None:
        if self._ended:
            return
        if len(self._items) >= self._maxsize:
            self._items.popleft()
            self.dropped += 1
        self._items.append(item)
        self._wake()

    def _end(self, error: BaseException | None = None) -> None:
        if self._ended:
            return
        self._ended = True
        self._error = error
        self._wake()

    def _wake(self) -> None:
        w = self._waiter
        if w is not None and not w.done():
            w.set_result(None)

    @property
    def closed(self) -> bool:
        return self._ended and not self._items

    def __aiter__(self) -> _Stream[T]:
        return self

    async def __anext__(self) -> T:
        while not self._items:
            if self._ended:
                if self._error is not None:
                    raise self._error
                raise StopAsyncIteration
            self._waiter = asyncio.get_running_loop().create_future()
            try:
                await self._waiter
            finally:
                self._waiter = None
        return self._items.popleft()

    async def get(self, timeout: float | None = None) -> T:
        """The next item (``StopAsyncIteration`` once the stream has ended)."""
        return await asyncio.wait_for(self.__anext__(), timeout)


class ReportStream(_Stream[Report]):
    """Every report received by a client (see :meth:`Client.reports`)."""

    def __init__(self, client: Client, maxsize: int) -> None:
        super().__init__(maxsize)
        self._client = client

    def close(self) -> None:
        self._client._router.streams.discard(self)
        self._end()


class ReportSubscription(_Stream[Report]):
    """Reports of one RCB enabled with :meth:`Client.enable_reporting`.

    ``async for report in subscription:`` yields them until reporting is disabled or the client
    closed (then the iteration stops), or the association is lost without recovery (then the
    loss error is raised). With a ``callback`` the reports are handed to it instead (a coroutine
    function is scheduled as a task) and the iterator yields nothing.
    """

    def __init__(
        self,
        client: Client,
        rcb: ObjectReference,
        callback: Callable[[Report], Any] | None,
        maxsize: int,
    ) -> None:
        super().__init__(maxsize)
        self._client = client
        self.rcb = rcb
        self.callback = callback
        self.values: RcbValues | None = None  # read back before RptEna was set

    def _put(self, item: Report) -> None:
        if self.callback is None:
            super()._put(item)
            return
        loop = asyncio.get_running_loop()
        try:
            r = self.callback(item)
            if inspect.isawaitable(r):
                loop.create_task(_awaitable(r))
        except Exception as e:  # noqa: BLE001 - reported to the loop like a callback error
            loop.call_exception_handler(
                {"message": "report callback failed", "exception": e, "subscription": self}
            )

    @property
    def last_entry_id(self) -> EntryID | None:
        return self._client.last_entry_id(self.rcb)

    async def trigger_gi(self) -> None:
        await self._client.trigger_gi(self.rcb)

    async def disable(self) -> None:
        """Disables reporting; reports already received are still delivered."""
        await self._client.disable_reporting(self.rcb)

    async def __aenter__(self) -> ReportSubscription:
        return self

    async def __aexit__(self, *exc: object) -> None:
        if not self._ended:
            try:
                await self.disable()
            except Iec61850Error:
                self._end()


async def _awaitable(a: Awaitable[Any]) -> Any:
    return await a


class EventStream(_Stream[ConnectionEvent]):
    """Connection events of a client (see :meth:`Client.events`); ends once the client is closed."""

    def __init__(self, client: Client, maxsize: int) -> None:
        super().__init__(maxsize)
        self._client = client

    def close(self) -> None:
        self._client._event_streams.discard(self)
        self._end()


class _Router:
    """Pulls reports from the native client and routes them to subscriptions and streams."""

    def __init__(self, client: Client) -> None:
        self.client = client
        self.subscriptions: dict[str, ReportSubscription] = {}
        self.streams: set[ReportStream] = set()
        self.task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self.task is None:
            self.task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        error: BaseException | None = None
        try:
            while True:
                raw = await self.client._native.next_report()
                report = self.client._make_report(raw)
                if report.rcb is not None:
                    sub = self.subscriptions.get(str(report.rcb))
                    if sub is not None:
                        sub._put(report)
                for s in list(self.streams):
                    s._put(report)
        except ConnectionClosed:
            error = None
        except Iec61850Error as e:
            error = e
        except asyncio.CancelledError:
            error = None
            raise
        finally:
            for sub in self.subscriptions.values():
                sub._end(error)
            for s in self.streams:
                s._end(error)
            self.task = None


# ---------------------------------------------------------------------------------------------
# Client


class Client:
    """IEC 61850 ACSI client over MMS (asyncio).

    Connect with :meth:`connect`, preferably as an async context manager::

        async with await Client.connect("10.0.0.5") as client:
            value = await client.read("IED1LD0/MMXU1.TotW.mag.f[MX]")

    Methods may be called concurrently (they share the association's request slots). A client
    belongs to the event loop it was connected from. Object references are accepted as ``str``
    or :class:`ObjectReference`; value conversions are described in ``openiec61850._values``.
    """

    def __init__(self, native: Any, edition: Edition) -> None:
        """Internal; use :meth:`connect`."""
        self._native = native
        self._edition = edition
        self._def_specs: dict[str, TypeSpec] = {}
        self._value_specs: dict[str, TypeSpec] = {}
        self._ds_specs: dict[str, list[TypeSpec | None]] = {}
        self._ds_members: dict[str, tuple[ObjectReference, ...]] = {}
        self._router = _Router(self)
        self._event_task: asyncio.Task[None] | None = None
        self._event_streams: set[EventStream] = set()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int = 102,
        *,
        password: str | None = None,
        timeout: float = 10.0,
        request_timeout: float = 10.0,
        release_timeout: float = 5.0,
        recovery: Recovery | bool | None = None,
        edition: Edition | int = Edition.ED2,
        strict_ln_names: bool = False,
        ap_title: str | Sequence[int] | None = DEFAULT_AP_TITLE,
        ae_qualifier: int | None = DEFAULT_AE_QUALIFIER,
        called_ap_title: str | Sequence[int] | None = DEFAULT_AP_TITLE,
        called_ae_qualifier: int | None = DEFAULT_AE_QUALIFIER,
        iso: IsoParameters | None = None,
        report_queue_capacity: int = 1024,
        event_queue_capacity: int = 64,
        file_transfer_timeout: float = 300.0,
        tls: TlsConfig | None = None,
    ) -> Client:
        """Establishes the association.

        ``timeout`` bounds each connection phase (TCP connect, COTP handshake, association) and
        ``request_timeout`` every request (0 disables them), ``file_transfer_timeout`` every
        :meth:`write_file` and :meth:`upload_file`. ``password`` uses ACSE password
        authentication. ``ap_title``/``ae_qualifier`` are the calling AP-title and AE-qualifier
        (``None`` omits them); ``called_*`` the called ones. ``recovery=True`` (or a
        :class:`Recovery`) enables association recovery; the first connection is not retried.
        ``tls`` runs the association over TLS; such servers normally listen on :data:`TLS_PORT`.
        """
        options: dict[str, Any] = {
            "host": host,
            "port": port,
            "password": password,
            "connect_timeout": timeout,
            "handshake_timeout": timeout,
            "association_timeout": timeout,
            "request_timeout": request_timeout,
            "release_timeout": release_timeout,
            "calling_ap_title": _oid_text(ap_title),
            "calling_ae_qualifier": ae_qualifier,
            "called_ap_title": _oid_text(called_ap_title),
            "called_ae_qualifier": called_ae_qualifier,
            "edition": int(edition),
            "strict_ln_names": strict_ln_names,
            "report_queue_capacity": report_queue_capacity,
            "event_queue_capacity": event_queue_capacity,
            "file_transfer_timeout": file_transfer_timeout,
        }
        if tls is not None:
            options["tls"] = tls._native()
        if recovery is True:
            recovery = Recovery()
        if isinstance(recovery, Recovery):
            options["recovery"] = {
                "backoff": [float(s) for s in recovery.backoff],
                "max_attempts": recovery.max_attempts,
            }
        if iso is not None:
            for k, v in vars(iso).items():
                if v is not None:
                    options[k] = v
        native = await _core.Client.connect(options)
        return cls(native, Edition(edition))

    # --- lifecycle

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *exc: object) -> None:
        try:
            await self.close()
        except Iec61850Error:
            self.abort()

    async def close(self) -> None:
        """Orderly release (Conclude + A-RELEASE); stops recovery. No-op once closed."""
        if self.state == ConnectionState.CLOSED:
            return
        await self._native.release()

    def abort(self) -> None:
        """A-ABORT; stops recovery. Idempotent."""
        self._native.abort()

    async def wait_closed(self) -> Iec61850Error:
        """Waits until the client is closed; returns why (e.g. :class:`ConnectionClosed`)."""
        return await self._native.wait_closed()

    @property
    def state(self) -> ConnectionState:
        return ConnectionState(self._native.state)

    @property
    def edition(self) -> Edition:
        return self._edition

    @property
    def association_info(self) -> AssociationInfo:
        """Parameters negotiated by the current (or last) association."""
        d = self._native.association_info()
        return AssociationInfo(
            negotiated=NegotiatedParameters(**d["negotiated"]),
            peer_ap_title=d["peer_ap_title"],
            peer_ae_qualifier=d["peer_ae_qualifier"],
            local_endpoint=tuple(d["local_endpoint"]),
            remote_endpoint=tuple(d["remote_endpoint"]),
            tls=TlsSession(**d["tls"]) if d["tls"] is not None else None,
        )

    # --- directory and definition

    async def server_directory(self) -> list[str]:
        """GetServerDirectory(LOGICAL-DEVICE): the LD names."""
        return list(await self._native.server_directory())

    async def logical_device_directory(self, ld: str) -> list[str]:
        """GetLogicalDeviceDirectory: the LN names of an LD."""
        return list(await self._native.logical_device_directory(ld))

    async def logical_node_directory(self, ln: Ref) -> LogicalNodeDirectory:
        """GetLogicalNodeDirectory for every ACSI class (data objects, data sets, RCBs...)."""
        d = await self._native.logical_node_directory(_ref_text(ln))
        return LogicalNodeDirectory(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in d.items()})

    async def data_directory(self, ref: Ref) -> list[DataDirectoryEntry]:
        """GetDataDirectory: the children of an LN, DO or structured DA (with their FCs)."""
        entries = await self._native.data_directory(_ref_text(ref))
        return [DataDirectoryEntry(name, tuple(FC(f) for f in fcs)) for name, fcs in entries]

    async def data_definition(self, ref: Ref) -> DataDefinition:
        """GetDataDefinition. The definition is cached to type later writes of plain values."""
        d = await self._native.data_definition(_ref_text(ref))
        if ObjectReference(_ref_text(ref), edition=self._edition, strict_ln_names=False).fc is not None:
            self._def_specs[_canonical(ref, self._edition)] = spec_from_definition(d)
        return DataDefinition._from(d)

    async def name_list(self, object_class: ObjectClass | int, domain: str = "") -> list[str]:
        """Generic MMS GetNameList (all continuations); ``domain=""`` is VMD scope."""
        return list(await self._native.name_list(int(object_class), domain))

    # --- data access

    async def read(self, ref: Ref) -> Any:
        """GetDataValues of one functionally constrained reference."""
        t = await self._native.read(_ref_text(ref))
        key = _canonical(ref, self._edition)
        self._value_specs[key] = spec_from_tagged(t)
        return decode(t, self._lookup_def(key))

    async def read_many(self, refs: Iterable[Ref], *, return_exceptions: bool = False) -> list[Any]:
        """One Read request for several references.

        A failed item raises its error (the first one), or with ``return_exceptions=True`` is
        returned in place as the exception instance.
        """
        refs = list(refs)
        results = await self._native.read_many([_ref_text(r) for r in refs])
        out: list[Any] = []
        for r, (ok, t) in zip(refs, results):
            if ok:
                key = _canonical(r, self._edition)
                self._value_specs[key] = spec_from_tagged(t)
                out.append(decode(t, self._lookup_def(key)))
            else:
                out.append(t)
        return _check_results(out, return_exceptions)

    async def write(self, ref: Ref, value: Any) -> None:
        """SetDataValues of one reference. See ``openiec61850._values`` for how ``value`` is typed."""
        t = await self._encode_for(ref, value)
        await self._native.write(_ref_text(ref), t)

    async def write_many(
        self,
        items: Mapping[Ref, Any] | Iterable[tuple[Ref, Any]],
        *,
        return_exceptions: bool = False,
    ) -> list[None | Iec61850Error]:
        """One Write request for several ``(reference, value)`` pairs."""
        pairs = list(items.items()) if isinstance(items, Mapping) else list(items)
        encoded = [(_ref_text(r), await self._encode_for(r, v)) for r, v in pairs]
        results = await self._native.write_many(encoded)
        return _check_results(list(results), return_exceptions)

    async def _encode_for(self, ref: Ref, value: Any) -> tuple[Any, ...]:
        key = _canonical(ref, self._edition)
        spec = self._lookup_def(key) or self._value_specs.get(key)
        try:
            return encode(value, spec)
        except TypeNeeded:
            if self._lookup_def(key) is not None:
                raise
        await self.data_definition(ref)
        return encode(value, self._lookup_def(key))

    def _lookup_def(self, key: str) -> TypeSpec | None:
        """The definition spec of a reference, from its own definition or an ancestor's."""
        spec = self._def_specs.get(key)
        if spec is not None or not self._def_specs:
            return spec
        try:
            ref = ObjectReference(key, edition=self._edition, strict_ln_names=False)
        except InvalidReference:
            return None
        path: list[Any] = []
        while ref.depth > 0:
            leaf = ref.leaf
            assert leaf is not None
            path.append(leaf)
            ref = ref.parent
            spec = self._def_specs.get(str(ref))
            if spec is not None:
                break
        if spec is None:
            return None
        for element in reversed(path):
            spec = spec.child(element.name)
            if spec is not None and element.index is not None:
                spec = spec.element()
            if spec is None:
                return None
        return spec

    # --- data sets

    async def data_set_directory(self, data_set: Ref) -> DataSetDirectory:
        """GetDataSetDirectory: the members (FCD/FCDA references)."""
        members, deletable = await self._native.data_set_directory(_ref_text(data_set))
        refs = tuple(ObjectReference(m, edition=self._edition, strict_ln_names=False) for m in members)
        self._ds_members[_canonical(data_set, self._edition)] = refs
        return DataSetDirectory(refs, deletable)

    async def create_data_set(self, data_set: Ref, members: Iterable[Ref]) -> None:
        """CreateDataSet: ``LD/LN.name`` is persistent, ``@name`` exists for this association only."""
        await self._native.create_data_set(_ref_text(data_set), [_ref_text(m) for m in members])

    async def delete_data_set(self, data_set: Ref) -> None:
        await self._native.delete_data_set(_ref_text(data_set))

    async def data_set_values(self, data_set: Ref, *, return_exceptions: bool = False) -> list[Any]:
        """GetDataSetValues (one value per member; failed members as in :meth:`read_many`)."""
        results = await self._native.data_set_values(_ref_text(data_set))
        key = _canonical(data_set, self._edition)
        members = self._ds_members.get(key)
        specs: list[TypeSpec | None] = []
        out: list[Any] = []
        for i, (ok, t) in enumerate(results):
            if ok:
                spec = self._lookup_def(str(members[i])) if members and i < len(members) else None
                specs.append(spec or spec_from_tagged(t))
                out.append(decode(t, spec))
            else:
                specs.append(None)
                out.append(t)
        self._ds_specs[key] = specs
        return _check_results(out, return_exceptions)

    async def set_data_set_values(
        self, data_set: Ref, values: Sequence[Any], *, return_exceptions: bool = False
    ) -> list[None | Iec61850Error]:
        """SetDataSetValues. Plain values are typed from the last :meth:`data_set_values`
        (read automatically when needed)."""
        key = _canonical(data_set, self._edition)

        def encode_all() -> list[tuple[Any, ...]]:
            specs = self._ds_specs.get(key, [])
            return [encode(v, specs[i] if i < len(specs) else None) for i, v in enumerate(values)]

        try:
            encoded = encode_all()
        except TypeNeeded:
            if key in self._ds_specs:
                raise
            await self.data_set_values(data_set, return_exceptions=True)
            encoded = encode_all()
        results = await self._native.set_data_set_values(_ref_text(data_set), encoded)
        return _check_results(list(results), return_exceptions)

    # --- reporting

    async def rcb_values(self, rcb: Ref) -> RcbValues:
        """GetBRCBValues / GetURCBValues; ``rcb`` is ``LD/LN.name[BR]`` or ``[RP]``."""
        return RcbValues._from(await self._native.rcb_values(_ref_text(rcb)))

    async def set_rcb_values(self, rcb: Ref, settings: RcbSettings | None = None, **changes: Any) -> None:
        """SetBRCBValues / SetURCBValues; stops at the first failing attribute.

        Pass an :class:`RcbSettings` or its fields as keywords.
        """
        s = settings if settings is not None else RcbSettings(**changes)
        await self._native.set_rcb_values(_ref_text(rcb), s._native())

    async def enable_reporting(
        self,
        rcb: Ref,
        *,
        rpt_id: str | None = None,
        data_set: Ref | None = None,
        opt_flds: OptFlds | int | None = None,
        trg_ops: TrgOps | int | None = None,
        buf_tm: int | None = None,
        intg_pd: int | None = None,
        reserve: bool = True,
        resv_tms: int | None = None,
        entry_id: EntryID | bytes | None = None,
        purge_buffer: bool = False,
        gi: bool = False,
        callback: Callable[[Report], Any] | None = None,
        queue_size: int = 1024,
    ) -> ReportSubscription:
        """Reserves (URCB), configures and enables an RCB; then a GI when ``gi`` is set.

        Returns a :class:`ReportSubscription` (also an async context manager that disables
        reporting on exit). ``opt_flds`` is masked to the bits a client may configure;
        ``entry_id`` resumes a BRCB after that entry. The RCB is re-enabled automatically by
        association recovery.
        """
        rcb_ref = ObjectReference(_ref_text(rcb), edition=self._edition, strict_ln_names=False)
        settings = {
            "rpt_id": rpt_id,
            "data_set": _ref_text(data_set) if data_set is not None else None,
            "opt_flds": int(opt_flds) if opt_flds is not None else None,
            "trg_ops": int(trg_ops) if trg_ops is not None else None,
            "buf_tm": buf_tm,
            "intg_pd": intg_pd,
            "reserve": reserve,
            "resv_tms": resv_tms,
            "entry_id": bytes(entry_id) if entry_id is not None else None,
            "purge_buffer": purge_buffer,
            "general_interrogation": gi,
        }
        sub = ReportSubscription(self, rcb_ref, callback, queue_size)
        key = str(rcb_ref)
        previous = self._router.subscriptions.get(key)
        self._router.subscriptions[key] = sub
        self._router.start()
        try:
            sub.values = RcbValues._from(await self._native.enable_reporting(key, settings))
        except BaseException:
            if self._router.subscriptions.get(key) is sub:
                if previous is not None:
                    self._router.subscriptions[key] = previous
                else:
                    del self._router.subscriptions[key]
            raise
        if previous is not None and previous is not sub:
            previous._end()
        return sub

    async def disable_reporting(self, rcb: Ref) -> None:
        """RptEna = false (and Resv = false for a URCB reserved by this client)."""
        key = _canonical(rcb, self._edition)
        await self._native.disable_reporting(_ref_text(rcb))
        sub = self._router.subscriptions.pop(key, None)
        if sub is not None:
            sub._end()

    async def trigger_gi(self, rcb: Ref) -> None:
        """GI = true on an enabled RCB."""
        await self._native.trigger_gi(_ref_text(rcb))

    # --- control

    async def control(
        self,
        ref: Ref,
        *,
        ctl_model: CtlModel | int | None = None,
        read_sbo_timeout: bool = True,
        read_structure: bool = True,
    ) -> Control:
        """A handle on the controllable data object ``ref`` (``LD/LN.DO``, or ``LD/LN.DO(i)`` for an
        element of an array of data objects; an FC is ignored).

        Reads CF.ctlModel (unless ``ctl_model`` is given), CF.sboTimeout and the CO structure
        (which types plain ctlVal values and tells which components to send).
        """
        native = await self._native.control(
            _ref_text(ref), int(ctl_model) if ctl_model is not None else None, read_sbo_timeout, read_structure
        )
        return Control(native, self._edition)

    async def operate(
        self,
        ref: Ref,
        value: Any,
        *,
        test: bool = False,
        interlock_check: bool = False,
        synchro_check: bool = False,
        origin: Originator | None = None,
        oper_time: Any = None,
        ctl_num: int | None = None,
        termination_timeout: float = 10.0,
    ) -> None:
        """One-shot control: by ctlModel, operate (direct), select + operate (SBO) or
        select_with_value + operate (SBO enhanced, also waiting for the CommandTermination).
        Keywords as for :meth:`Control.operate`."""
        opts = _options(
            test=test,
            interlock_check=interlock_check,
            synchro_check=synchro_check,
            origin=origin,
            oper_time=oper_time,
            ctl_num=ctl_num,
            termination_timeout=termination_timeout,
        )
        try:
            t = encode(value)
        except TypeNeeded:
            # A plain value: type it from the object's CO structure.
            ctl = await self.control(ref)
            t = ctl._value(value)
        await self._native.operate(_ref_text(ref), t, opts)

    # --- setting groups (IEC 61850-7-2 §16), on the SGCB "LD/LLN0.SGCB[SP]"

    async def sgcb_values(self, ld: str) -> SgcbValues:
        """GetSGCBValues of logical device ``ld``."""
        d = await self._native.sgcb_values(ld)
        return SgcbValues(
            num_of_sgs=d["num_of_sgs"],
            act_sg=d["act_sg"],
            edit_sg=d["edit_sg"],
            cnf_edit=d["cnf_edit"],
            lact_tm=_ts(d["lact_tm"]),
            resv_tms=d["resv_tms"],
        )

    async def select_active_sg(self, ld: str, sg: int) -> None:
        """SelectActiveSG: activates setting group ``sg`` (1-based)."""
        await self._native.select_active_sg(ld, int(sg))

    async def select_edit_sg(self, ld: str, sg: int) -> None:
        """SelectEditSG: copies group ``sg`` to the edit buffer and reserves it for this
        association; 0 releases it."""
        await self._native.select_edit_sg(ld, int(sg))

    async def set_edit_sg_value(self, ref: Ref, value: Any) -> None:
        """SetEditSGValue: writes an FC SE reference of the edit buffer. Plain values are typed
        like :meth:`write` (the definition is read when needed)."""
        t = await self._encode_for(ref, value)
        await self._native.set_edit_sg_value(_ref_text(ref), t)

    async def confirm_edit_sg_values(self, ld: str) -> None:
        """ConfirmEditSGValues: stores the edit buffer into the group being edited."""
        await self._native.confirm_edit_sg_values(ld)

    async def edit_sg_value(self, ref: Ref) -> Any:
        """GetEditSGValue: the value of an FC SE (edit buffer) or SG (active group) reference."""
        t = await self._native.edit_sg_value(_ref_text(ref))
        key = _canonical(ref, self._edition)
        self._value_specs[key] = spec_from_tagged(t)
        return decode(t, self._lookup_def(key))

    # --- logs (IEC 61850-7-2 §17.3); ``lcb`` is "LD/LN.name[LG]", ``log`` is "LD/LN.LogName"

    async def lcb_values(self, lcb: Ref) -> LcbValues:
        """GetLCBValues."""
        d = await self._native.lcb_values(_ref_text(lcb))
        return LcbValues(
            log_ena=d["log_ena"],
            log_ref=d["log_ref"],
            dat_set=d["dat_set"],
            old_entr_tm=EntryTime(*d["old_entr_tm"]) if d["old_entr_tm"] is not None else None,
            new_entr_tm=EntryTime(*d["new_entr_tm"]) if d["new_entr_tm"] is not None else None,
            old_ent=EntryID(d["old_ent"]) if d["old_ent"] is not None else None,
            new_ent=EntryID(d["new_ent"]) if d["new_ent"] is not None else None,
            trg_ops=TrgOps(d["trg_ops"] & 0x7E) if d["trg_ops"] is not None else None,
            intg_pd=d["intg_pd"],
        )

    async def set_lcb_values(self, lcb: Ref, settings: LcbSettings | None = None, **changes: Any) -> None:
        """SetLCBValues; stops at the first failing attribute. Pass an :class:`LcbSettings` or its
        fields as keywords."""
        s = settings if settings is not None else LcbSettings(**changes)
        await self._native.set_lcb_values(_ref_text(lcb), s._native())

    async def query_log_by_time(
        self,
        log: Ref,
        start: EntryTime | datetime | None = None,
        stop: EntryTime | datetime | None = None,
    ) -> list[LogEntry]:
        """QueryLogByTime: the entries from ``start`` to ``stop`` (None: open ended), following
        the server's continuations."""
        raw = await self._native.query_log_by_time(_ref_text(log), _entry_time(start), _entry_time(stop))
        return [self._log_entry(e) for e in raw]

    async def query_log_after(self, log: Ref, time: EntryTime | datetime, entry_id: EntryID | bytes) -> list[LogEntry]:
        """QueryLogAfter: the entries after ``entry_id`` (``time`` is used when the server no
        longer has that entry)."""
        raw = await self._native.query_log_after(_ref_text(log), _entry_time(time), bytes(entry_id))
        return [self._log_entry(e) for e in raw]

    async def log_entries(
        self,
        log: Ref,
        start: EntryTime | datetime | None = None,
        stop: EntryTime | datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """The entries of :meth:`query_log_by_time` as an async iterator."""
        for e in await self.query_log_by_time(log, start, stop):
            yield e

    async def log_status(self, log: Ref) -> int:
        """GetLogStatus: the number of entries in the log."""
        return int(await self._native.log_status(_ref_text(log)))

    def _log_entry(self, e: tuple[Any, ...]) -> LogEntry:
        entry_id, time, data = e
        items = []
        for reference, tagged, reason in data:
            spec = None
            try:
                spec = self._lookup_def(str(ObjectReference.from_mms(reference)))
            except (InvalidReference, ValueError):
                pass
            items.append(
                LogEntryData(
                    reference=reference,
                    value=decode(tagged, spec),
                    reason=TrgOps(reason & 0x7E) if reason is not None else None,
                )
            )
        return LogEntry(EntryID(entry_id), EntryTime(*time), tuple(items))

    # --- files (IEC 61850-7-2 §23); names are "/"-separated paths

    async def list_files(self, path: str = "") -> list[FileEntry]:
        """GetServerDirectory(FILE): the files below ``path`` ("" for every file)."""
        out = []
        for name, size, mtime in await self._native.file_directory(path):
            when = datetime.fromtimestamp(mtime, timezone.utc) if mtime is not None else None
            out.append(FileEntry(name, size, when))
        return out

    async def read_file(self, name: str) -> bytes:
        """GetFile: the whole content (FileOpen, FileRead until the end, FileClose)."""
        return bytes(await self._native.get_file(name))

    async def download_file(
        self,
        name: str,
        dest: str | os.PathLike[str] | IO[bytes],
        *,
        on_chunk: Callable[[int], Any] | None = None,
    ) -> int:
        """GetFile streamed into ``dest`` (a path, created or truncated, or a binary file object)
        chunk by chunk as the FileRead responses arrive; returns the number of octets.

        Chunks are written on the event loop thread (the native client never waits for it).
        ``on_chunk(total_so_far)`` is called after each chunk. On failure a file created from a
        path is removed.
        """
        own = isinstance(dest, (str, os.PathLike))
        f: IO[bytes] = open(dest, "wb") if own else dest  # type: ignore[arg-type,assignment]  # noqa: SIM115
        state = {"done": False, "total": 0, "error": None}

        def chunk(data: bytes) -> None:
            if state["done"] or state["error"] is not None:
                return
            try:
                f.write(data)
                state["total"] += len(data)  # type: ignore[operator]
                if on_chunk is not None:
                    on_chunk(state["total"])
            except Exception as e:  # noqa: BLE001 - reported when the download ends
                state["error"] = e

        try:
            n = int(await self._native.get_file_stream(name, chunk))
            if state["error"] is not None:
                raise state["error"]  # type: ignore[misc]
        except BaseException:
            state["done"] = True
            if own:
                f.close()
                try:
                    os.unlink(dest)  # type: ignore[arg-type]
                except OSError:
                    pass
            raise
        state["done"] = True
        if own:
            f.close()
        return n

    async def write_file(self, name: str, content: bytes) -> None:
        """SetFile: ``name`` is created on the server (ObtainFile), which reads ``content`` back
        from this client before it answers; an existing name is refused."""
        await self._native.set_file(name, bytes(content))

    async def upload_file(
        self,
        name: str,
        source: str | os.PathLike[str] | IO[bytes],
        *,
        source_name: str | None = None,
    ) -> int:
        """SetFile from ``source`` (a path, or a seekable binary file object), read chunk by chunk
        as the server asks for it; returns the number of octets.

        Reads run on the I/O thread, so a file object must answer quickly and never wait for the
        event loop. The server is told to read ``source_name`` (default: ``name``), and only
        that name is served, only until this call ends. A failure to read ``source`` is raised
        as such.
        """
        own = isinstance(source, (str, os.PathLike))
        f: IO[bytes] = open(source, "rb") if own else source  # type: ignore[arg-type,assignment]  # noqa: SIM115
        failure: list[Exception] = []
        try:
            size = f.seek(0, os.SEEK_END)

            def reader(offset: int, n: int) -> bytes:
                try:
                    f.seek(offset)
                    return f.read(n)
                except Exception as e:  # noqa: BLE001 - raised when the transfer ends
                    failure.append(e)
                    return b""  # a short read fails the server's FileRead

            try:
                await self._native.set_file_stream(name, size, reader, source_name or "")
            except Iec61850Error:
                if failure:
                    raise failure[0] from None
                raise
            return size
        finally:
            if own:
                f.close()

    async def delete_file(self, name: str) -> None:
        """FileDelete."""
        await self._native.delete_file(name)

    async def rename_file(self, current: str, new: str) -> None:
        """FileRename."""
        await self._native.rename_file(current, new)

    # --- GOOSE control blocks (IEC 61850-7-2 §18.2); ``gocb`` is "LD/LN.name[GO]"

    async def gocb_values(self, gocb: Ref) -> GoCBValues:
        """GetGoCBValues."""
        d = await self._native.gocb_values(_ref_text(gocb))
        addr = d["dst_address"]
        return GoCBValues(
            go_ena=d["go_ena"],
            go_id=d["go_id"],
            dat_set=d["dat_set"],
            conf_rev=d["conf_rev"],
            nds_com=d["nds_com"],
            dst_address=GooseAddress(bytes(addr[0]), addr[1], addr[2], addr[3]) if addr is not None else None,
            min_time=d["min_time"],
            max_time=d["max_time"],
            fixed_offs=d["fixed_offs"],
        )

    async def set_gocb_values(self, gocb: Ref, settings: GoCBSettings | None = None, **changes: Any) -> None:
        """SetGoCBValues; stops at the first failing attribute. Pass a :class:`GoCBSettings` or
        its fields as keywords."""
        s = settings if settings is not None else GoCBSettings(**changes)
        await self._native.set_gocb_values(_ref_text(gocb), s._native())

    def last_entry_id(self, rcb: Ref) -> EntryID | None:
        """The EntryID of the last report received for a BRCB enabled by this client."""
        b = self._native.last_entry_id(_ref_text(rcb))
        return EntryID(b) if b is not None else None

    @property
    def reports_dropped(self) -> int:
        """Reports dropped by the native queue overflow or because they could not be parsed."""
        return int(self._native.reports_dropped)

    def reports(self, *, queue_size: int = 1024) -> ReportStream:
        """Every report received, including those not matched to an enabled RCB."""
        stream = ReportStream(self, queue_size)
        self._router.streams.add(stream)
        self._router.start()
        return stream

    def events(self, *, queue_size: int = 64) -> EventStream:
        """Connection events (lost / reconnecting / restored / failed) from now on; events
        queued natively before the first call are delivered too."""
        stream = EventStream(self, queue_size)
        self._event_streams.add(stream)
        if self._event_task is None:
            self._event_task = asyncio.get_running_loop().create_task(self._pump_events())
        return stream

    async def _pump_events(self) -> None:
        try:
            while True:
                d = await self._native.next_event()
                event = ConnectionEvent(
                    kind=EventKind(d["kind"]),
                    error=d["error"],
                    attempt=d["attempt"],
                    rcb_errors=tuple(
                        (ObjectReference(r, edition=self._edition, strict_ln_names=False), e)
                        for r, e in d["rcb_errors"]
                    ),
                )
                for s in list(self._event_streams):
                    s._put(event)
        except Iec61850Error:
            pass
        finally:
            for s in self._event_streams:
                s._end()
            self._event_task = None

    def _make_report(self, d: Mapping[str, Any]) -> Report:
        entries = []
        for e in d["entries"]:
            ref = _ref(e["reference"], self._edition)
            spec = self._lookup_def(str(ref)) if ref is not None else None
            entries.append(
                ReportEntry(
                    index=e["index"],
                    data_reference=e["data_reference"],
                    reference=ref,
                    value=decode(e["value"], spec),
                    reason=TrgOps(e["reason"]) if e["reason"] is not None else None,
                )
            )
        return Report(
            rpt_id=d["rpt_id"],
            opt_flds=OptFlds(d["opt_flds"]),
            seq_num=d["seq_num"],
            time_of_entry=EntryTime(*d["time_of_entry"]) if d["time_of_entry"] is not None else None,
            data_set=d["data_set"],
            buffer_overflow=d["buffer_overflow"],
            entry_id=EntryID(d["entry_id"]) if d["entry_id"] is not None else None,
            conf_rev=d["conf_rev"],
            sub_seq_num=d["sub_seq_num"],
            more_segments_follow=d["more_segments_follow"],
            inclusion=tuple(d["inclusion"]),
            entries=tuple(entries),
            rcb=_ref(d["rcb"], self._edition),
            lost_before=d["lost_before"],
        )


def _oid_text(v: str | Sequence[int] | None) -> str | None:
    if v is None or isinstance(v, str):
        return v
    return ".".join(str(int(a)) for a in v)


def _check_results(results: list[Any], return_exceptions: bool) -> list[Any]:
    if not return_exceptions:
        for i, r in enumerate(results):
            if isinstance(r, BaseException):
                if isinstance(r, Iec61850Error):
                    r.index = i  # type: ignore[attr-defined]
                raise r
    return results

