"""GOOSE (IEC 61850-8-1 §18) and Sampled Values (IEC 61850-9-2) publishers and subscribers.

Frames travel on a layer 2 :class:`Link`: a :class:`LoopbackNetwork` link (in memory, for tests and
simulations) or a :class:`RawSocketLink` (Linux AF_PACKET, needs CAP_NET_RAW)::

    net = LoopbackNetwork()
    pub_link, sub_link = net.attach("00-00-00-00-00-01"), net.attach("00-00-00-00-00-02")
    cfg = GoosePublisherConfig(gocb_ref="IED1LD0/LLN0$GO$gcb01", dat_set="IED1LD0/LLN0$DS1",
                               go_id="GO1", app_id=0x1000)
    pub = GoosePublisher(pub_link, cfg, [False, Quality()])
    pub.start()

    async with Receiver(sub_link) as rx:
        sub = rx.subscribe(GooseSubscriberConfig(gocb_ref=cfg.gocb_ref))
        async for event in sub:
            if event.kind is GooseEventKind.MESSAGE:
                print(event.message.st_num, event.message.values)

Values are typed Python values (``bool``, :class:`~openiec61850.Int32`,
:class:`~openiec61850.Float32`, :class:`~openiec61850.Quality`, :class:`~openiec61850.Timestamp`,
:class:`~openiec61850.BitString`...); after the first message a publisher also accepts plain
``int`` / ``float`` / ``str`` values, typed like the previous ones.

Threading: the native publishers, the receiver and the subscriptions run on the shared I/O thread.
A subscription delivers its events to the event loop it was created from, in batches: the I/O
thread queues the events (bounded by ``queue_capacity``; the oldest are dropped and counted) and
hands everything queued to the loop in one ``call_soon_threadsafe`` whenever the consumer has
used the previous batch. A slow consumer therefore gets large batches instead of a flooded loop.

Sampled Values in Python: a 9-2 LE stream is 4000 or 4800 ASDUs per second per merging unit
(12800 / 15360 for the metering profile). Each ASDU delivered to Python costs a few microseconds
(object creation), so one stream fits comfortably, several streams with a busy loop may not. Use
:meth:`SvSubscriber.batches` to consume lists of samples (one wake-up per batch), keep the
per-sample work small, and watch :attr:`SvSubscriber.dropped`. For protection-grade processing
(every sample, bounded latency), use the C++ API (``sv::subscriber::set_handler``).
:meth:`SvPublisher.start` drives a publisher from a timer on the I/O thread calling a Python
source per sample: for tests and simulations only (OS timer jitter, GIL); a real merging unit
emulation calls :meth:`SvPublisher.push` from its own sampling loop.
"""

from __future__ import annotations

import asyncio
import collections
import enum
import os
import struct
import time
import weakref
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, Union

from openiec61850 import _core
from openiec61850._errors import wait_for
from openiec61850._types import Timestamp, Validity
from openiec61850._values import TypeSpec, decode, encode, spec_from_tagged

__all__ = [
    "FrameHeader",
    "GooseSequenceCheck",
    "Link",
    "LoopbackNetwork",
    "SequenceTracker",
    "SmpCntTracker",
    "SvAsdu",
    "SvFrame",
    "decode_frame",
    "decode_goose",
    "decode_sv",
    "encode_goose",
    "encode_sv",
    "is_multicast",
    "peek_ether_type",
    "retransmission_interval",
    "samples_per_second",
    "RawSocketLink",
    "VlanTag",
    "GoosePublisherConfig",
    "GoosePublisher",
    "GooseSubscriberConfig",
    "GooseSubscriber",
    "GooseEvent",
    "GooseEventKind",
    "GooseMessage",
    "MismatchReason",
    "SequenceStatus",
    "Receiver",
    "SvPublisherConfig",
    "SvPublisher",
    "SvSubscriberConfig",
    "SvSubscriber",
    "SvSample",
    "Continuity",
    "SmpSynch",
    "SampleMode",
    "LeSamples",
    "ETHERTYPE_GOOSE",
    "ETHERTYPE_GSE_MANAGEMENT",
    "ETHERTYPE_SV",
    "ETHERTYPE_VLAN",
    "SAMPLES_PER_PERIOD_METERING",
    "SAMPLES_PER_PERIOD_PROTECTION",
]

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_GOOSE = 0x88B8
ETHERTYPE_GSE_MANAGEMENT = 0x88B9
ETHERTYPE_SV = 0x88BA
SAMPLES_PER_PERIOD_PROTECTION = 80
SAMPLES_PER_PERIOD_METERING = 256

Mac = Union[str, bytes]
T = TypeVar("T")


def _mac(m: Mac) -> bytes:
    b = bytes(m) if isinstance(m, (bytes, bytearray)) else bytes.fromhex(m.replace("-", "").replace(":", ""))
    if len(b) != 6:
        raise ValueError(f"a MAC address has 6 octets: {m!r}")
    return b


def _opt_mac(m: Mac | None) -> bytes | None:
    return None if m is None else _mac(m)


def _mac_text(b: bytes | None) -> str | None:
    return None if b is None else "-".join(f"{x:02X}" for x in b)


def _scl_source(scl: str | os.PathLike[str] | bytes) -> tuple[str, bool]:
    if isinstance(scl, (bytes, bytearray)):
        return bytes(scl).decode("utf-8"), True
    if isinstance(scl, str) and scl.lstrip().startswith("<"):
        return scl, True
    return os.fspath(scl), False


def _from_scl(kind: str, scl: Any, ied: str, ld_inst: str, cb_name: str, access_point: str | None,
              frequency: int = 50) -> dict[str, Any]:
    text, is_text = _scl_source(scl)
    return _core.goose_config_from_scl(kind, text, is_text, ied, ld_inst, cb_name, access_point or "", frequency)


# ---------------------------------------------------------------------------------------------
# Links


class Link:
    """A layer 2 link (whole Ethernet frames without FCS)."""

    def __init__(self, native: Any) -> None:
        """Internal; use :meth:`LoopbackNetwork.attach` or :meth:`RawSocketLink.open`."""
        self._native = native

    @property
    def address(self) -> str:
        """The hardware address, the default source of publishers."""
        return _mac_text(self._native.address)  # type: ignore[return-value]

    @property
    def dropped(self) -> int | None:
        """Loopback links: frames dropped because the receive queue was full."""
        return self._native.dropped

    def send(self, frame: bytes) -> None:
        """Sends one raw frame (e.g. a crafted one in a test)."""
        self._native.send(bytes(frame))

    def close(self) -> None:
        """Stops the link; idempotent."""
        self._native.close()

    def __enter__(self) -> Link:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.address})"


class LoopbackNetwork:
    """An in-memory broadcast domain: a frame sent on one link reaches every other link."""

    def __init__(self) -> None:
        self._native = _core.LoopbackNetwork()

    def attach(self, address: Mac = "02-00-00-00-00-01", *, queue_capacity: int = 1024) -> Link:
        """A new link with that hardware address (``queue_capacity`` frames buffered)."""
        return Link(self._native.attach(_mac(address), int(queue_capacity)))

    @property
    def frames_sent(self) -> int:
        return int(self._native.frames_sent)

    def set_filter(self, keep: Callable[[bytes, str], bool] | None) -> None:
        """Loss injection for tests: ``keep(frame, to)`` runs on the sender's thread for every
        frame and receiving link (its address); False drops the frame for that link. An exception
        keeps the frame. ``None`` removes the filter."""
        if keep is None:
            self._native.set_filter(None)
            return

        def native(frame: bytes, to: bytes) -> bool:
            return bool(keep(frame, _mac_text(to)))  # type: ignore[arg-type]

        self._native.set_filter(native)


class RawSocketLink(Link):
    """A Linux AF_PACKET link bound to one interface."""

    @classmethod
    def open(
        cls,
        interface: str,
        *,
        ether_types: Iterable[int] = (ETHERTYPE_GOOSE, ETHERTYPE_SV),
        promiscuous: bool = False,
        all_multicast: bool = True,
        multicast_groups: Iterable[Mac] = (),
        receive_outgoing: bool = False,
        socket_priority: int = -1,
    ) -> RawSocketLink:
        """Opens ``interface`` (e.g. "eth0"). ``ether_types`` is a kernel filter (empty: every
        frame). Raises :class:`~openiec61850.CommunicationError` with ``errno`` EPERM without
        CAP_NET_RAW, ENODEV for an unknown interface; :class:`~openiec61850.NotSupported` off
        Linux."""
        options = {
            "interface_name": interface,
            "ether_types": [int(t) for t in ether_types],
            "promiscuous": promiscuous,
            "all_multicast": all_multicast,
            "multicast_groups": [_mac(m) for m in multicast_groups],
            "receive_outgoing": receive_outgoing,
            "socket_priority": int(socket_priority),
        }
        return cls(_core.GooseLink.open_raw(options))

    @property
    def interface_index(self) -> int:
        return int(self._native.interface_index)


@dataclass(frozen=True)
class VlanTag:
    """IEEE 802.1Q tag; priority 4 is the IEC 61850 default, id 0 is priority tagging only."""

    priority: int = 4
    dei: bool = False
    id: int = 0


def _vlan(v: VlanTag | None) -> tuple[int, bool, int] | None:
    return None if v is None else (int(v.priority), bool(v.dei), int(v.id))


def _vlan_from(t: Any) -> VlanTag | None:
    return None if t is None else VlanTag(t[0], bool(t[1]), t[2])


# ---------------------------------------------------------------------------------------------
# GOOSE publisher


@dataclass(frozen=True)
class GoosePublisherConfig:
    """A GOOSE publisher (8-1 §18.1). ``gocb_ref`` / ``dat_set`` in MMS form
    ("IED1LD0/LLN0$GO$gcb01", "IED1LD0/LLN0$DS1"); times in milliseconds. Retransmissions follow
    min(MinTime * 2^(n-1), MaxTime); timeAllowedtoLive is ``tal_multiplier`` x the next interval
    (or ``tal_override``)."""

    gocb_ref: str
    dat_set: str
    go_id: str = ""
    destination: Mac = "01-0C-CD-01-00-00"
    source: Mac | None = None  # the link address when None
    vlan: VlanTag | None = VlanTag()
    app_id: int = 0
    conf_rev: int = 1
    nds_com: bool = False
    simulation: bool = False
    min_time: int = 10
    max_time: int = 1000
    tal_multiplier: int = 2
    tal_override: int | None = None
    time_accuracy: int = 31

    def _native(self) -> dict[str, Any]:
        return {
            "destination": _mac(self.destination),
            "source": _opt_mac(self.source),
            "vlan": _vlan(self.vlan),
            "app_id": int(self.app_id),
            "gocb_ref": self.gocb_ref,
            "dat_set": self.dat_set,
            "go_id": self.go_id,
            "conf_rev": int(self.conf_rev),
            "nds_com": bool(self.nds_com),
            "simulation": bool(self.simulation),
            "min_time": int(self.min_time),
            "max_time": int(self.max_time),
            "tal_multiplier": int(self.tal_multiplier),
            "tal_override": None if self.tal_override is None else int(self.tal_override),
            "time_accuracy": int(self.time_accuracy),
        }

    @staticmethod
    def _from(d: dict[str, Any]) -> GoosePublisherConfig:
        return GoosePublisherConfig(
            gocb_ref=d["gocb_ref"],
            dat_set=d["dat_set"],
            go_id=d["go_id"],
            destination=_mac_text(d["destination"]),  # type: ignore[arg-type]
            source=_mac_text(d["source"]),
            vlan=_vlan_from(d["vlan"]),
            app_id=d["app_id"],
            conf_rev=d["conf_rev"],
            nds_com=d["nds_com"],
            simulation=d["simulation"],
            min_time=d["min_time"],
            max_time=d["max_time"],
            tal_multiplier=d["tal_multiplier"],
            tal_override=d["tal_override"],
            time_accuracy=d["time_accuracy"],
        )

    @classmethod
    def from_scl(
        cls, scl: str | os.PathLike[str] | bytes, ied: str, ld_inst: str, cb_name: str,
        access_point: str | None = None,
    ) -> GoosePublisherConfig:
        """From the GSEControl ``cb_name`` of LLN0 in IED ``ied`` / LD ``ld_inst`` and its GSE
        address (``scl``: a path or the SCL text)."""
        return cls._from(_from_scl("goose_publisher", scl, ied, ld_inst, cb_name, access_point))


@dataclass(frozen=True)
class GoosePublisherStats:
    st_num: int
    sq_num: int
    messages_sent: int
    send_errors: int
    last_error: BaseException | None


def _encode_values(values: Sequence[Any], specs: Sequence[TypeSpec | None]) -> list[tuple[Any, ...]]:
    return [encode(v, specs[i] if i < len(specs) else None) for i, v in enumerate(values)]


class GoosePublisher:
    """Publishes one GoCB on a link; every method is safe from any thread. Also a context
    manager (stops on exit)."""

    def __init__(self, link: Link, config: GoosePublisherConfig, values: Sequence[Any]) -> None:
        tagged = _encode_values(values, ())
        self._native = _core.GoosePublisher.create(link._native, config._native(), tagged)
        self._specs: list[TypeSpec | None] = [spec_from_tagged(t) for t in tagged]
        self.config = config

    def _tagged(self, values: Sequence[Any]) -> list[tuple[Any, ...]]:
        tagged = _encode_values(values, self._specs)
        self._specs = [spec_from_tagged(t) for t in tagged]
        return tagged

    def start(self) -> None:
        """Sends the first message (stNum 1) and starts the retransmissions."""
        self._native.start()

    def stop(self) -> None:
        self._native.stop()

    def publish(self, values: Sequence[Any], when: Timestamp | None = None) -> None:
        """A new state: stNum + 1, sent at once, then the fast retransmissions."""
        self._native.publish(self._tagged(values), encode(when) if when is not None else None)

    def update(self, values: Sequence[Any], when: Timestamp | None = None) -> bool:
        """Publishes only when the values changed; returns whether an event was generated."""
        return bool(self._native.update(self._tagged(values), encode(when) if when is not None else None))

    def set_nds_com(self, on: bool) -> None:
        self._native.set_nds_com(bool(on))

    def set_simulation(self, on: bool) -> None:
        self._native.set_simulation(bool(on))

    @property
    def stats(self) -> GoosePublisherStats:
        return GoosePublisherStats(**self._native.stats())

    def __enter__(self) -> GoosePublisher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


# ---------------------------------------------------------------------------------------------
# Subscriptions (common delivery)


class _Pump(Generic[T]):
    """The Python end of a native pump (python/src/pump.hpp)."""

    def __init__(self) -> None:
        self._items: collections.deque[Any] = collections.deque()
        self._waiter: asyncio.Future[None] | None = None
        self._ended = False
        self._error: BaseException | None = None
        self._requested = True  # the native pump starts armed
        self._native: Any = None

    @staticmethod
    def _sink(ref: weakref.ref[_Pump[Any]]) -> Callable[[Any], None]:
        # The native side owns the sink: it must not keep the stream alive.
        def sink(batch: Any) -> None:
            self = ref()
            if self is not None:
                self._feed(batch)

        return sink

    def _convert(self, raw: Any) -> T:
        raise NotImplementedError

    def _feed(self, batch: Any) -> None:
        self._requested = False
        for raw in batch.items():
            self._items.append(self._convert(raw))
        if batch.ended:
            self._ended = True
            self._error = batch.error
        w = self._waiter
        if w is not None and not w.done():
            w.set_result(None)

    async def _wait(self) -> bool:
        """Waits for items; False once the stream has ended and is drained."""
        while not self._items:
            if self._ended:
                if self._error is not None:
                    raise self._error
                return False
            if not self._requested:
                self._requested = True
                self._native.request()
            self._waiter = asyncio.get_running_loop().create_future()
            try:
                await self._waiter
            finally:
                self._waiter = None
        return True

    def __aiter__(self) -> _Pump[T]:
        return self

    async def __anext__(self) -> T:
        if not await self._wait():
            raise StopAsyncIteration
        return self._items.popleft()

    async def get(self, timeout: float | None = None) -> T:
        """The next item; ``TimeoutError`` after ``timeout`` seconds (nothing is lost),
        ``StopAsyncIteration`` once closed."""
        return await wait_for(self.__anext__(), timeout)

    async def get_batch(self, max_items: int | None = None, timeout: float | None = None) -> list[T]:
        """Everything delivered so far (at least one item, at most ``max_items``); an empty list
        once the stream has ended."""
        if not await wait_for(self._wait(), timeout):
            return []
        n = len(self._items) if max_items is None else min(max_items, len(self._items))
        return [self._items.popleft() for _ in range(n)]

    async def batches(self, max_items: int | None = None) -> AsyncIterator[list[T]]:
        """Lists of items as they are delivered (one wake-up per batch)."""
        while True:
            b = await self.get_batch(max_items)
            if not b:
                return
            yield b

    @property
    def closed(self) -> bool:
        return self._ended and not self._items

    @property
    def dropped(self) -> int:
        """Items dropped because the queue was full (the consumer was too slow)."""
        return int(self._native.dropped)

    def close(self) -> None:
        """Ends the subscription; items already delivered can still be read."""
        self._native.close()

    def _end_local(self) -> None:
        self._ended = True
        w = self._waiter
        if w is not None and not w.done():
            w.set_result(None)


# ---------------------------------------------------------------------------------------------
# GOOSE subscriber


class SequenceStatus(enum.IntEnum):
    """How a message relates to the previous one (stNum / sqNum)."""

    FIRST = 0
    NEW_STATE = 1
    RETRANSMISSION = 2
    SQ_GAP = 3
    ST_GAP = 4
    DUPLICATE = 5
    OUT_OF_ORDER = 6


class GooseEventKind(enum.IntEnum):
    MESSAGE = 0  # a valid message
    TIMEOUT = 1  # timeAllowedtoLive expired: the values are invalid until the next message
    MISMATCH = 2  # a message of the GoCB that disagrees with the configuration


class MismatchReason(enum.IntEnum):
    NONE = 0
    DAT_SET = 1
    GO_ID = 2
    CONF_REV = 3
    NUM_ENTRIES = 4
    NDS_COM = 5


@dataclass(frozen=True)
class GooseSubscriberConfig:
    """Selects a GoCB (``app_id``, ``destination``, ``gocb_ref``; None / "" = any) and the
    expected ``dat_set`` / ``go_id`` / ``conf_rev`` / ``num_entries`` (a disagreement is a
    MISMATCH event). ``tal_margin`` (ms) is added to every timeAllowedtoLive."""

    gocb_ref: str = ""
    app_id: int | None = None
    destination: Mac | None = None
    dat_set: str | None = None
    go_id: str | None = None
    conf_rev: int | None = None
    num_entries: int | None = None
    accept_simulation: bool = False
    tal_margin: int = 0
    queue_capacity: int = 256

    def _native(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "destination": _opt_mac(self.destination),
            "gocb_ref": self.gocb_ref,
            "dat_set": self.dat_set,
            "go_id": self.go_id,
            "conf_rev": self.conf_rev,
            "num_entries": self.num_entries,
            "accept_simulation": bool(self.accept_simulation),
            "tal_margin": int(self.tal_margin),
            "queue_capacity": int(self.queue_capacity),
        }

    @classmethod
    def from_scl(
        cls, scl: str | os.PathLike[str] | bytes, ied: str, ld_inst: str, cb_name: str,
        access_point: str | None = None,
    ) -> GooseSubscriberConfig:
        """Filters and expectations for the GSEControl ``cb_name`` of IED ``ied`` / LD
        ``ld_inst``."""
        d = _from_scl("goose_subscriber", scl, ied, ld_inst, cb_name, access_point)
        return cls(
            gocb_ref=d["gocb_ref"],
            app_id=d["app_id"],
            destination=_mac_text(d["destination"]),
            dat_set=d["dat_set"],
            go_id=d["go_id"],
            conf_rev=d["conf_rev"],
            num_entries=d["num_entries"],
            accept_simulation=d["accept_simulation"],
            tal_margin=d["tal_margin"],
            queue_capacity=d["queue_capacity"],
        )


@dataclass(frozen=True)
class GooseMessage:
    """A decoded GOOSE message (values decoded from their MMS types)."""

    destination: str
    source: str
    vlan: VlanTag | None
    app_id: int
    reserved1: int
    reserved2: int
    gocb_ref: str
    time_allowed_to_live: int  # ms
    dat_set: str
    go_id: str | None
    t: Timestamp
    st_num: int
    sq_num: int
    simulation: bool
    conf_rev: int
    nds_com: bool
    num_dat_set_entries: int
    values: tuple[Any, ...]
    sequence: SequenceStatus
    lost: int  # messages (sq gap) or state changes (st gap) known to be missing
    security: bytes | None = None  # decode_goose(): contents of the [12] field, not interpreted


@dataclass(frozen=True)
class GooseEvent:
    kind: GooseEventKind
    message: GooseMessage  # for TIMEOUT: the last message received (without values)
    reason: MismatchReason = MismatchReason.NONE
    dropped_before: int = 0


def _goose_event(d: dict[str, Any]) -> GooseEvent:
    m = d["message"]
    t = m["t"]
    msg = GooseMessage(
        destination=_mac_text(m["destination"]),  # type: ignore[arg-type]
        source=_mac_text(m["source"]),  # type: ignore[arg-type]
        vlan=_vlan_from(m["vlan"]),
        app_id=m["app_id"],
        reserved1=m["reserved1"],
        reserved2=m["reserved2"],
        gocb_ref=m["gocb_ref"],
        time_allowed_to_live=m["time_allowed_to_live"],
        dat_set=m["dat_set"],
        go_id=m["go_id"],
        t=Timestamp.from_raw(t[1], t[2], t[3]),
        st_num=m["st_num"],
        sq_num=m["sq_num"],
        simulation=m["simulation"],
        conf_rev=m["conf_rev"],
        nds_com=m["nds_com"],
        num_dat_set_entries=m["num_dat_set_entries"],
        values=tuple(decode(v) for v in m["values"]),
        sequence=SequenceStatus(m["sequence"]),
        lost=m["lost"],
        security=m.get("security"),
    )
    return GooseEvent(GooseEventKind(d["kind"]), msg, MismatchReason(d["reason"]), d["dropped_before"])


@dataclass(frozen=True)
class GooseSubscriberStats:
    messages: int
    timeouts: int
    mismatches: int
    lost: int
    duplicates: int
    out_of_order: int
    simulated_ignored: int
    dropped: int


class GooseSubscriber(_Pump[GooseEvent]):
    """The events of one GoCB (``async for event in subscriber``); created by
    :meth:`Receiver.subscribe`. :meth:`batches` yields lists instead."""

    def __init__(self, receiver: Receiver, config: GooseSubscriberConfig, max_batch: int) -> None:
        """Internal; use :meth:`Receiver.subscribe`."""
        super().__init__()
        self.config = config
        self._native = receiver._native.subscribe_goose(config._native(), _Pump._sink(weakref.ref(self)), max_batch)

    def _convert(self, raw: Any) -> GooseEvent:
        return _goose_event(raw)

    @property
    def stats(self) -> GooseSubscriberStats:
        return GooseSubscriberStats(**self._native.stats())


# ---------------------------------------------------------------------------------------------
# Sampled Values


class SmpSynch(enum.IntEnum):
    NONE = 0
    LOCAL = 1
    GLOBAL = 2


class SampleMode(enum.IntEnum):
    SAMPLES_PER_PERIOD = 0
    SAMPLES_PER_SECOND = 1
    SECONDS_PER_SAMPLE = 2


class Continuity(enum.IntEnum):
    """smpCnt continuity of an ASDU."""

    FIRST = 0
    IN_SEQUENCE = 1
    GAP = 2
    DUPLICATE = 3
    OUT_OF_ORDER = 4


_LE = struct.Struct(">" + "iI" * 8)
_AMPERES_PER_LSB = 0.001
_VOLTS_PER_LSB = 0.01
_INT32 = (-(1 << 31), (1 << 31) - 1)


def _scaled(x: float, lsb: float) -> int:
    v = round(x / lsb)
    return max(_INT32[0], min(_INT32[1], v))


@dataclass(frozen=True)
class LeSamples:
    """One 9-2 LE ASDU: IA, IB, IC, IN (1 mA per LSB) and VA, VB, VC, VN (10 mV per LSB), each an
    INT32 value with a 32-bit quality (9-2 §8.6: bits 0-1 validity, bit 13 derived)."""

    values: tuple[int, ...] = (0,) * 8
    qualities: tuple[int, ...] = (0,) * 8

    DERIVED = 1 << 13

    @classmethod
    def from_measurements(
        cls,
        currents: Sequence[float] = (0.0, 0.0, 0.0, 0.0),
        voltages: Sequence[float] = (0.0, 0.0, 0.0, 0.0),
        qualities: Sequence[int] | None = None,
    ) -> LeSamples:
        """From amperes and volts (rounded to the LSB, saturated to INT32)."""
        if len(currents) != 4 or len(voltages) != 4:
            raise ValueError("9-2 LE has 4 currents and 4 voltages")
        values = tuple(_scaled(c, _AMPERES_PER_LSB) for c in currents) + tuple(
            _scaled(v, _VOLTS_PER_LSB) for v in voltages
        )
        return cls(values, tuple(qualities) if qualities is not None else (0,) * 8)

    @property
    def currents(self) -> tuple[float, ...]:
        return tuple(v * _AMPERES_PER_LSB for v in self.values[:4])

    @property
    def voltages(self) -> tuple[float, ...]:
        return tuple(v * _VOLTS_PER_LSB for v in self.values[4:])

    def validity(self, channel: int) -> Validity:
        return Validity(self.qualities[channel] & 0x3)

    def derived(self, channel: int) -> bool:
        return bool(self.qualities[channel] & self.DERIVED)

    def encode(self) -> bytes:
        """The 64-octet seqData."""
        if len(self.values) != 8 or len(self.qualities) != 8:
            raise ValueError("9-2 LE has 8 channels")
        flat: list[int] = []
        for v, q in zip(self.values, self.qualities):
            flat += (int(v), int(q) & 0xFFFFFFFF)
        return _LE.pack(*flat)

    @classmethod
    def decode(cls, seq_data: bytes) -> LeSamples:
        """``ValueError`` unless ``seq_data`` is 64 octets."""
        if len(seq_data) != _LE.size:
            raise ValueError("9-2 LE seqData is 64 octets")
        flat = _LE.unpack(seq_data)
        return cls(tuple(flat[0::2]), tuple(flat[1::2]))


@dataclass(frozen=True)
class SvPublisherConfig:
    """An SV publisher (MSVCB). Each pushed sample is one ASDU; a frame carries
    ``asdus_per_frame`` of them. smpCnt wraps at ``smp_cnt_wrap`` (0: 65536)."""

    sv_id: str
    dat_set: str | None = None
    destination: Mac = "01-0C-CD-04-00-00"
    source: Mac | None = None
    vlan: VlanTag | None = VlanTag()
    app_id: int = 0x4000
    simulation: bool = False
    conf_rev: int = 1
    smp_synch: int = SmpSynch.NONE
    smp_rate: int | None = None
    smp_mod: int | None = None
    refresh_time: bool = False
    asdus_per_frame: int = 1
    smp_cnt_wrap: int = 4000

    def _native(self) -> dict[str, Any]:
        return {
            "destination": _mac(self.destination),
            "source": _opt_mac(self.source),
            "vlan": _vlan(self.vlan),
            "app_id": int(self.app_id),
            "simulation": bool(self.simulation),
            "sv_id": self.sv_id,
            "dat_set": self.dat_set,
            "conf_rev": int(self.conf_rev),
            "smp_synch": int(self.smp_synch),
            "smp_rate": self.smp_rate,
            "smp_mod": self.smp_mod,
            "refresh_time": bool(self.refresh_time),
            "asdus_per_frame": int(self.asdus_per_frame),
            "smp_cnt_wrap": int(self.smp_cnt_wrap),
        }

    @classmethod
    def from_scl(
        cls, scl: str | os.PathLike[str] | bytes, ied: str, ld_inst: str, cb_name: str,
        access_point: str | None = None, frequency: int = 50,
    ) -> SvPublisherConfig:
        """From the SampledValueControl ``cb_name`` and its SMV address; ``frequency`` (Hz) sets
        the smpCnt wrap for samples-per-period rates."""
        d = _from_scl("sv_publisher", scl, ied, ld_inst, cb_name, access_point, frequency)
        return cls(
            sv_id=d["sv_id"],
            dat_set=d["dat_set"],
            destination=_mac_text(d["destination"]),  # type: ignore[arg-type]
            source=_mac_text(d["source"]),
            vlan=_vlan_from(d["vlan"]),
            app_id=d["app_id"],
            simulation=d["simulation"],
            conf_rev=d["conf_rev"],
            smp_synch=d["smp_synch"],
            smp_rate=d["smp_rate"],
            smp_mod=d["smp_mod"],
            refresh_time=d["refresh_time"],
            asdus_per_frame=d["asdus_per_frame"],
            smp_cnt_wrap=d["smp_cnt_wrap"],
        )


@dataclass(frozen=True)
class SvPublisherStats:
    samples: int
    frames_sent: int
    send_errors: int
    next_smp_cnt: int


def _seq_data(s: bytes | LeSamples) -> bytes:
    return s.encode() if isinstance(s, LeSamples) else s


class SvPublisher:
    """Publishes one SV stream on a link."""

    def __init__(self, link: Link, config: SvPublisherConfig) -> None:
        self._native = _core.SvPublisher.create(link._native, config._native())
        self.config = config

    def push(self, sample: bytes | LeSamples, refr_tm: Timestamp | None = None) -> int:
        """Adds one sample with the next smpCnt (returned) and sends the frame once complete. Not
        thread-safe: one caller at a time, and not while :meth:`start` runs."""
        return int(self._native.push(_seq_data(sample), encode(refr_tm) if refr_tm is not None else None))

    def start(self, period: float, source: Callable[[int], bytes | LeSamples]) -> None:
        """Calls ``source(smp_cnt)`` every ``period`` seconds on the I/O thread (holding the GIL)
        and publishes what it returns. For tests and simulations only (see the module docs)."""

        def src(cnt: int) -> bytes:
            return _seq_data(source(cnt))

        self._native.start(float(period), src)

    def stop(self) -> None:
        self._native.stop()

    @property
    def stats(self) -> SvPublisherStats:
        return SvPublisherStats(**self._native.stats())

    def __enter__(self) -> SvPublisher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


@dataclass(frozen=True)
class SvSubscriberConfig:
    """Selects an SV stream (``app_id``, ``destination``, ``sv_id``; None / "" = any); a
    different ``conf_rev`` is flagged on each sample. ``smp_cnt_wrap``: the counter range (0:
    unknown)."""

    sv_id: str = ""
    app_id: int | None = None
    destination: Mac | None = None
    conf_rev: int | None = None
    smp_cnt_wrap: int = 0
    accept_simulation: bool = False
    queue_capacity: int = 4096

    def _native(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "destination": _opt_mac(self.destination),
            "sv_id": self.sv_id,
            "conf_rev": self.conf_rev,
            "smp_cnt_wrap": int(self.smp_cnt_wrap),
            "accept_simulation": bool(self.accept_simulation),
            "queue_capacity": int(self.queue_capacity),
        }

    @classmethod
    def from_scl(
        cls, scl: str | os.PathLike[str] | bytes, ied: str, ld_inst: str, cb_name: str,
        access_point: str | None = None, frequency: int = 50,
    ) -> SvSubscriberConfig:
        d = _from_scl("sv_subscriber", scl, ied, ld_inst, cb_name, access_point, frequency)
        return cls(
            sv_id=d["sv_id"],
            app_id=d["app_id"],
            destination=_mac_text(d["destination"]),
            conf_rev=d["conf_rev"],
            smp_cnt_wrap=d["smp_cnt_wrap"],
            accept_simulation=d["accept_simulation"],
            queue_capacity=d["queue_capacity"],
        )


@dataclass(frozen=True)
class SvSample:
    """One received ASDU. ``le`` decodes a 9-2 LE ``seq_data``."""

    source: str
    app_id: int
    simulation: bool
    sv_id: str
    dat_set: str | None
    smp_cnt: int
    conf_rev: int
    refr_tm: Timestamp | None
    smp_synch: int
    smp_rate: int | None
    smp_mod: int | None
    seq_data: bytes
    status: Continuity
    lost: int
    conf_rev_mismatch: bool

    @property
    def le(self) -> LeSamples:
        return LeSamples.decode(self.seq_data)


_CONTINUITY = tuple(Continuity)


def _sv_sample(t: tuple[Any, ...]) -> SvSample:
    refr = t[7]
    return SvSample(
        _mac_text(t[0]),  # type: ignore[arg-type]
        t[1],
        t[2],
        t[3],
        t[4],
        t[5],
        t[6],
        Timestamp.from_raw(refr[1], refr[2], refr[3]) if refr is not None else None,
        t[8],
        t[9],
        t[10],
        t[11],
        _CONTINUITY[t[12]],
        t[13],
        t[14],
    )


@dataclass(frozen=True)
class SvSubscriberStats:
    samples: int
    lost: int
    duplicates: int
    out_of_order: int
    conf_rev_mismatches: int
    simulated_ignored: int
    dropped: int


class SvSubscriber(_Pump[SvSample]):
    """The samples of one SV stream: ``async for sample in sub`` one by one, or
    ``async for batch in sub.batches()`` as lists (preferred at 4 kHz and above)."""

    def __init__(self, receiver: Receiver, config: SvSubscriberConfig, max_batch: int) -> None:
        """Internal; use :meth:`Receiver.subscribe_sv`."""
        super().__init__()
        self.config = config
        self._native = receiver._native.subscribe_sv(config._native(), _Pump._sink(weakref.ref(self)), max_batch)

    def _convert(self, raw: Any) -> SvSample:
        return _sv_sample(raw)

    @property
    def stats(self) -> SvSubscriberStats:
        return SvSubscriberStats(**self._native.stats())


# ---------------------------------------------------------------------------------------------
# Frames and supervision without I/O


@dataclass(frozen=True)
class FrameHeader:
    """The Ethernet / 802.1Q / APPID header of a GOOSE, GSE management or SV frame."""

    destination: str
    source: str
    vlan: VlanTag | None
    ether_type: int
    app_id: int
    length: int
    reserved1: int
    reserved2: int
    apdu: bytes

    @property
    def simulation(self) -> bool:
        """The Reserved1 S bit (Ed.2)."""
        return (self.reserved1 & 0x8000) != 0


def decode_frame(frame: bytes) -> FrameHeader:
    """Decodes the header of a frame; padding after Length is ignored."""
    d = _core.goose_decode_frame(bytes(frame))
    return FrameHeader(
        _mac_text(d["destination"]),  # type: ignore[arg-type]
        _mac_text(d["source"]),  # type: ignore[arg-type]
        _vlan_from(d["vlan"]),
        d["ether_type"],
        d["app_id"],
        d["length"],
        d["reserved1"],
        d["reserved2"],
        bytes(d["apdu"]),
    )


def peek_ether_type(frame: bytes) -> int:
    """The EtherType of a frame (after an optional 802.1Q tag), or 0."""
    return int(_core.goose_peek_ether_type(bytes(frame)))


def is_multicast(mac: Mac) -> bool:
    return (_mac(mac)[0] & 1) != 0


def _header(destination: Mac, source: Mac, vlan: VlanTag | None, app_id: int, reserved1: int,
            reserved2: int) -> dict[str, Any]:
    return {
        "destination": _mac(destination),
        "source": _mac(source),
        "vlan": _vlan(vlan),
        "app_id": int(app_id),
        "reserved1": int(reserved1),
        "reserved2": int(reserved2),
    }


def encode_goose(
    destination: Mac,
    source: Mac,
    *,
    gocb_ref: str,
    dat_set: str,
    values: Sequence[Any],
    go_id: str = "",
    time_allowed_to_live: int = 0,
    t: Timestamp | None = None,
    st_num: int = 1,
    sq_num: int = 0,
    simulation: bool = False,
    conf_rev: int = 1,
    nds_com: bool = False,
    num_dat_set_entries: int | None = None,
    vlan: VlanTag | None = VlanTag(),
    app_id: int = 0,
    reserved1: int = 0,
    reserved2: int = 0,
) -> bytes:
    """One complete GOOSE frame, e.g. to craft a message in a test (``Link.send`` sends it)."""
    fields = {
        "gocb_ref": gocb_ref,
        "dat_set": dat_set,
        "go_id": go_id,
        "time_allowed_to_live": int(time_allowed_to_live),
        "t": encode(t) if t is not None else None,
        "st_num": int(st_num),
        "sq_num": int(sq_num),
        "simulation": bool(simulation),
        "conf_rev": int(conf_rev),
        "nds_com": bool(nds_com),
        "num_dat_set_entries": num_dat_set_entries,
    }
    tagged = _encode_values(values, ())
    header = _header(destination, source, vlan, app_id, reserved1, reserved2)
    return bytes(_core.goose_encode(header, fields, tagged))


def decode_goose(frame: bytes) -> GooseMessage:
    """Decodes a whole GOOSE frame (the sequence fields stay at their defaults)."""
    return _goose_event(_core.goose_decode(bytes(frame))).message


@dataclass(frozen=True)
class SvAsdu:
    """One ASDU of a savPdu, without the subscription's supervision (:class:`SvSample`)."""

    sv_id: str
    seq_data: bytes | LeSamples
    dat_set: str | None = None
    smp_cnt: int = 0
    conf_rev: int = 1
    refr_tm: Timestamp | None = None
    smp_synch: int = SmpSynch.NONE
    smp_rate: int | None = None
    smp_mod: int | None = None
    gm_identity: bytes | None = None

    def _native(self) -> dict[str, Any]:
        return {
            "sv_id": self.sv_id,
            "seq_data": _seq_data(self.seq_data),
            "dat_set": self.dat_set,
            "smp_cnt": int(self.smp_cnt),
            "conf_rev": int(self.conf_rev),
            "refr_tm": encode(self.refr_tm) if self.refr_tm is not None else None,
            "smp_synch": int(self.smp_synch),
            "smp_rate": self.smp_rate,
            "smp_mod": self.smp_mod,
            "gm_identity": self.gm_identity,
        }


@dataclass(frozen=True)
class SvFrame:
    """A decoded SV frame."""

    header: FrameHeader
    asdus: tuple[SvAsdu, ...]
    security: bytes | None = None  # not interpreted


def encode_sv(
    destination: Mac,
    source: Mac,
    asdus: Iterable[SvAsdu],
    *,
    vlan: VlanTag | None = VlanTag(),
    app_id: int = 0x4000,
    reserved1: int = 0,
    reserved2: int = 0,
) -> bytes:
    """One complete SV frame."""
    header = _header(destination, source, vlan, app_id, reserved1, reserved2)
    return bytes(_core.sv_encode(header, [a._native() for a in asdus]))


def decode_sv(frame: bytes) -> SvFrame:
    """Decodes a whole SV frame."""
    data = bytes(frame)
    asdus, security = _core.sv_decode(data)
    out = []
    for d in asdus:
        refr = d["refr_tm"]
        refr_tm = Timestamp.from_raw(refr[1], refr[2], refr[3]) if refr is not None else None
        out.append(SvAsdu(**{**d, "refr_tm": refr_tm, "seq_data": bytes(d["seq_data"])}))
    return SvFrame(decode_frame(data), tuple(out), bytes(security) if security is not None else None)


def retransmission_interval(sq_num: int, min_time: int, max_time: int) -> int:
    """The interval in ms before the message with ``sq_num`` (>= 1) of a publisher:
    min(MinTime * 2^(n-1), MaxTime)."""
    return int(_core.goose_retransmission_interval(int(sq_num), int(min_time), int(max_time)))


def samples_per_second(per_period: int, frequency: int) -> int:
    """The smpCnt wrap of samples-per-period rates: 4000 for 80 per period at 50 Hz..."""
    return int(per_period) * int(frequency)


@dataclass(frozen=True)
class GooseSequenceCheck:
    status: SequenceStatus
    lost: int  # messages (SQ_GAP) or state changes (ST_GAP) known to be missing


class SequenceTracker:
    """stNum / sqNum / timeAllowedtoLive supervision of one GoCB, without I/O: what a subscription
    does for each message, for frames obtained elsewhere (e.g. a capture). Times are in seconds
    of one monotonic clock, :func:`time.monotonic` by default. ``margin`` (ms) is added to every
    TAL."""

    def __init__(self, *, margin: int = 0) -> None:
        self._native = _core.SequenceTracker()
        self._native.margin = int(margin)

    def on_message(self, st_num: int, sq_num: int, tal_ms: int, now: float | None = None) -> GooseSequenceCheck:
        """Records a message and arms the TAL deadline."""
        status, lost = self._native.on_message(st_num, sq_num, tal_ms, time.monotonic() if now is None else now)
        return GooseSequenceCheck(SequenceStatus(status), lost)

    def expired(self, now: float | None = None) -> bool:
        """True once ``now`` is past the deadline of the last message."""
        return bool(self._native.expired(time.monotonic() if now is None else now))

    @property
    def deadline(self) -> float | None:
        return self._native.deadline

    def reset(self) -> None:
        """Forgets the previous message: the next one is FIRST."""
        self._native.reset()

    @property
    def has_state(self) -> bool:
        return bool(self._native.has_state)

    @property
    def st_num(self) -> int:
        return int(self._native.st_num)

    @property
    def sq_num(self) -> int:
        return int(self._native.sq_num)


class SmpCntTracker:
    """smpCnt continuity of one SV stream, without I/O. ``wrap``: the counter range (0: unknown,
    a drop to 0 from any value is taken as the wrap)."""

    def __init__(self, wrap: int = 0) -> None:
        self._native = _core.SmpCntTracker(int(wrap))

    def on_sample(self, smp_cnt: int) -> tuple[Continuity, int]:
        """The continuity of this sample and the samples known to be lost."""
        status, lost = self._native.on_sample(int(smp_cnt))
        return _CONTINUITY[status], lost

    def reset(self) -> None:
        self._native.reset()


# ---------------------------------------------------------------------------------------------
# Receiver


@dataclass(frozen=True)
class ReceiverStats:
    frames: int
    malformed: int
    unmatched: int
    other: int


class Receiver:
    """Reads a link and dispatches GOOSE and SV frames to its subscriptions. Create the
    subscriptions from a running event loop (they deliver to it). Also an (async) context
    manager: started on entry, stopped on exit."""

    def __init__(self, link: Link, *, start: bool = True) -> None:
        self._native = _core.Receiver(link._native)
        self._subs: weakref.WeakSet[_Pump[Any]] = weakref.WeakSet()
        if start:
            self.start()

    def start(self) -> None:
        self._native.start()

    def stop(self) -> None:
        """Stops the loop and ends every subscription (their queued items stay readable)."""
        self._native.stop()
        for s in list(self._subs):
            s.close()

    def subscribe(self, config: GooseSubscriberConfig | None = None, *, max_batch: int = 64,
                  **filters: Any) -> GooseSubscriber:
        """A GOOSE subscription (pass a config or its fields as keywords)."""
        cfg = config if config is not None else GooseSubscriberConfig(**filters)
        s = GooseSubscriber(self, cfg, max_batch)
        self._subs.add(s)
        return s

    def subscribe_sv(self, config: SvSubscriberConfig | None = None, *, max_batch: int = 1024,
                     **filters: Any) -> SvSubscriber:
        """An SV subscription; ``max_batch`` bounds the samples per delivered batch."""
        cfg = config if config is not None else SvSubscriberConfig(**filters)
        s = SvSubscriber(self, cfg, max_batch)
        self._subs.add(s)
        return s

    @property
    def stats(self) -> ReceiverStats:
        return ReceiverStats(**self._native.stats())

    def __enter__(self) -> Receiver:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    async def __aenter__(self) -> Receiver:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.stop()
