"""Blocking facade over the asyncio client and server (ADR 0004: a thin synchronous wrapper).

Every :class:`Client` method has the same name and arguments as in :class:`openiec61850.Client`
and blocks the calling thread (without holding the GIL) until it completes. The asyncio clients
run on one private event loop in a background daemon thread shared by all synchronous clients;
report callbacks run on that thread. :class:`Server` mirrors :class:`openiec61850.Server` the
same way (awaitables returned by its ``on_control`` hook run on that loop).

>>> from openiec61850.sync import Client
>>> with Client.connect("10.0.0.5") as c:                        # doctest: +SKIP
...     print(c.read("IED1LD0/MMXU1.TotW.mag.f[MX]"))
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import threading
from datetime import datetime
from collections.abc import Callable, Coroutine, Iterable, Iterator, Mapping, Sequence
from typing import IO, Any, Generic, TypeVar

from openiec61850 import _client, _control, _server
from openiec61850._client import (
    AssociationInfo,
    FileEntry,
    GoCBSettings,
    GoCBValues,
    LcbSettings,
    LcbValues,
    LogEntry,
    SgcbValues,
    ConnectionEvent,
    ConnectionState,
    DataDefinition,
    DataDirectoryEntry,
    DataSetDirectory,
    LogicalNodeDirectory,
    RcbSettings,
    RcbValues,
    Report,
    Ref,
)
from openiec61850._errors import Iec61850Error
from openiec61850._control import LastApplError
from openiec61850._types import CtlModel, EntryID, EntryTime, ObjectClass, ObjectReference

__all__ = ["Client", "Control", "ReportSubscription", "ReportStream", "EventStream", "Server"]

T = TypeVar("T")


class _LoopThread:
    _lock = threading.Lock()
    _loop: asyncio.AbstractEventLoop | None = None

    @classmethod
    def loop(cls) -> asyncio.AbstractEventLoop:
        with cls._lock:
            if cls._loop is None or cls._loop.is_closed():
                loop = asyncio.new_event_loop()
                ready = threading.Event()

                def run() -> None:
                    asyncio.set_event_loop(loop)
                    loop.call_soon(ready.set)
                    loop.run_forever()

                threading.Thread(target=run, name="openiec61850-sync", daemon=True).start()
                ready.wait()
                cls._loop = loop
            return cls._loop


def _run(coro: Coroutine[Any, Any, T], timeout: float | None = None) -> T:
    loop = _LoopThread.loop()
    if threading.current_thread().name == "openiec61850-sync":
        coro.close()
        raise RuntimeError("blocking openiec61850.sync calls are not allowed on its loop thread")
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return fut.result(timeout)
    except concurrent.futures.TimeoutError:
        # Since Python 3.11 this is the builtin TimeoutError, which openiec61850.Timeout also is.
        if fut.done():
            raise
        fut.cancel()
        raise TimeoutError("the operation did not complete in time") from None
    except BaseException:
        fut.cancel()
        raise


class _SyncStream(Generic[T]):
    def __init__(self, stream: _client._Stream[T]) -> None:
        self._stream = stream

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        try:
            return _run(self._stream.__anext__())
        except StopAsyncIteration:
            raise StopIteration from None

    def get(self, timeout: float | None = None) -> T:
        """The next item; ``TimeoutError`` after ``timeout`` seconds, ``StopIteration`` at the end."""
        try:
            return _run(self._stream.__anext__(), timeout)
        except StopAsyncIteration:
            raise StopIteration from None

    @property
    def closed(self) -> bool:
        return self._stream.closed

    @property
    def dropped(self) -> int:
        return self._stream.dropped


class ReportSubscription(_SyncStream[Report]):
    """Blocking iterator over the reports of one RCB; also a context manager (disables on exit)."""

    _stream: _client.ReportSubscription

    @property
    def rcb(self) -> _client.ObjectReference:
        return self._stream.rcb

    @property
    def values(self) -> RcbValues | None:
        return self._stream.values

    @property
    def last_entry_id(self) -> EntryID | None:
        return self._stream.last_entry_id

    def trigger_gi(self) -> None:
        _run(self._stream.trigger_gi())

    def disable(self) -> None:
        _run(self._stream.disable())

    def __enter__(self) -> ReportSubscription:
        return self

    def __exit__(self, *exc: object) -> None:
        _run(self._stream.__aexit__(*exc))


class ReportStream(_SyncStream[Report]):
    _stream: _client.ReportStream

    def close(self) -> None:
        _LoopThread.loop().call_soon_threadsafe(self._stream.close)


class EventStream(_SyncStream[ConnectionEvent]):
    _stream: _client.EventStream

    def close(self) -> None:
        _LoopThread.loop().call_soon_threadsafe(self._stream.close)


class Control:
    """Blocking control handle; see :class:`openiec61850.Control` for the semantics."""

    def __init__(self, inner: _control.Control) -> None:
        """Internal; use :meth:`Client.control`."""
        self._c = inner

    def __repr__(self) -> str:
        return repr(self._c)

    @property
    def aio(self) -> _control.Control:
        return self._c

    @property
    def reference(self) -> ObjectReference:
        return self._c.reference

    @property
    def ctl_model(self) -> CtlModel:
        return self._c.ctl_model

    @property
    def sbo_timeout(self) -> float | None:
        return self._c.sbo_timeout

    @property
    def ctl_num(self) -> int:
        return self._c.ctl_num

    @property
    def selected(self) -> bool:
        return self._c.selected

    @property
    def has_oper_time(self) -> bool | None:
        return self._c.has_oper_time

    @property
    def last_error(self) -> LastApplError | None:
        return self._c.last_error

    def select(self, **options: Any) -> None:
        _run(self._c.select(**options))

    def select_with_value(self, value: Any, **options: Any) -> None:
        _run(self._c.select_with_value(value, **options))

    def operate(self, value: Any, **options: Any) -> None:
        """Same keywords as :meth:`openiec61850.Control.operate`."""
        _run(self._c.operate(value, **options))

    def cancel(self, **options: Any) -> None:
        _run(self._c.cancel(**options))


class Client:
    """Blocking IEC 61850 client; see :class:`openiec61850.Client` for the semantics."""

    def __init__(self, inner: _client.Client) -> None:
        """Internal; use :meth:`connect`."""
        self._c = inner

    @classmethod
    def connect(cls, host: str, port: int = 102, **options: Any) -> Client:
        """Same keywords as :meth:`openiec61850.Client.connect`."""
        return cls(_run(_client.Client.connect(host, port, **options)))

    @property
    def aio(self) -> _client.Client:
        """The underlying asyncio client (lives on the facade's loop thread)."""
        return self._c

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self.close()
        except Iec61850Error:
            self.abort()

    def close(self) -> None:
        _run(self._c.close())

    def abort(self) -> None:
        self._c.abort()

    def wait_closed(self, timeout: float | None = None) -> Iec61850Error:
        return _run(self._c.wait_closed(), timeout)

    @property
    def state(self) -> ConnectionState:
        return self._c.state

    @property
    def association_info(self) -> AssociationInfo:
        return self._c.association_info

    def server_directory(self) -> list[str]:
        return _run(self._c.server_directory())

    def logical_device_directory(self, ld: str) -> list[str]:
        return _run(self._c.logical_device_directory(ld))

    def logical_node_directory(self, ln: Ref) -> LogicalNodeDirectory:
        return _run(self._c.logical_node_directory(ln))

    def data_directory(self, ref: Ref) -> list[DataDirectoryEntry]:
        return _run(self._c.data_directory(ref))

    def data_definition(self, ref: Ref) -> DataDefinition:
        return _run(self._c.data_definition(ref))

    def name_list(self, object_class: ObjectClass | int, domain: str = "") -> list[str]:
        return _run(self._c.name_list(object_class, domain))

    def read(self, ref: Ref) -> Any:
        return _run(self._c.read(ref))

    def read_many(self, refs: Iterable[Ref], *, return_exceptions: bool = False) -> list[Any]:
        return _run(self._c.read_many(list(refs), return_exceptions=return_exceptions))

    def write(self, ref: Ref, value: Any) -> None:
        _run(self._c.write(ref, value))

    def write_many(
        self, items: Mapping[Ref, Any] | Iterable[tuple[Ref, Any]], *, return_exceptions: bool = False
    ) -> list[None | Iec61850Error]:
        items = dict(items) if isinstance(items, Mapping) else list(items)
        return _run(self._c.write_many(items, return_exceptions=return_exceptions))

    def data_set_directory(self, data_set: Ref) -> DataSetDirectory:
        return _run(self._c.data_set_directory(data_set))

    def create_data_set(self, data_set: Ref, members: Iterable[Ref]) -> None:
        _run(self._c.create_data_set(data_set, list(members)))

    def delete_data_set(self, data_set: Ref) -> None:
        _run(self._c.delete_data_set(data_set))

    def data_set_values(self, data_set: Ref, *, return_exceptions: bool = False) -> list[Any]:
        return _run(self._c.data_set_values(data_set, return_exceptions=return_exceptions))

    def set_data_set_values(
        self, data_set: Ref, values: Sequence[Any], *, return_exceptions: bool = False
    ) -> list[None | Iec61850Error]:
        return _run(self._c.set_data_set_values(data_set, list(values), return_exceptions=return_exceptions))

    def rcb_values(self, rcb: Ref) -> RcbValues:
        return _run(self._c.rcb_values(rcb))

    def set_rcb_values(self, rcb: Ref, settings: RcbSettings | None = None, **changes: Any) -> None:
        _run(self._c.set_rcb_values(rcb, settings, **changes))

    def enable_reporting(
        self, rcb: Ref, *, callback: Callable[[Report], Any] | None = None, **settings: Any
    ) -> ReportSubscription:
        """Same keywords as :meth:`openiec61850.Client.enable_reporting`; ``callback`` runs on
        the facade's loop thread."""
        return ReportSubscription(_run(self._c.enable_reporting(rcb, callback=callback, **settings)))

    def disable_reporting(self, rcb: Ref) -> None:
        _run(self._c.disable_reporting(rcb))

    def trigger_gi(self, rcb: Ref) -> None:
        _run(self._c.trigger_gi(rcb))

    def control(self, ref: Ref, **options: Any) -> Control:
        """Same keywords as :meth:`openiec61850.Client.control`."""
        return Control(_run(self._c.control(ref, **options)))

    def operate(self, ref: Ref, value: Any, **options: Any) -> None:
        """Same keywords as :meth:`openiec61850.Client.operate`."""
        _run(self._c.operate(ref, value, **options))

    def last_entry_id(self, rcb: Ref) -> EntryID | None:
        return self._c.last_entry_id(rcb)

    # setting groups

    def sgcb_values(self, ld: str) -> SgcbValues:
        return _run(self._c.sgcb_values(ld))

    def select_active_sg(self, ld: str, sg: int) -> None:
        _run(self._c.select_active_sg(ld, sg))

    def select_edit_sg(self, ld: str, sg: int) -> None:
        _run(self._c.select_edit_sg(ld, sg))

    def set_edit_sg_value(self, ref: Ref, value: Any) -> None:
        _run(self._c.set_edit_sg_value(ref, value))

    def confirm_edit_sg_values(self, ld: str) -> None:
        _run(self._c.confirm_edit_sg_values(ld))

    def edit_sg_value(self, ref: Ref) -> Any:
        return _run(self._c.edit_sg_value(ref))

    # logs

    def lcb_values(self, lcb: Ref) -> LcbValues:
        return _run(self._c.lcb_values(lcb))

    def set_lcb_values(self, lcb: Ref, settings: LcbSettings | None = None, **changes: Any) -> None:
        _run(self._c.set_lcb_values(lcb, settings, **changes))

    def query_log_by_time(
        self, log: Ref, start: EntryTime | datetime | None = None, stop: EntryTime | datetime | None = None
    ) -> list[LogEntry]:
        return _run(self._c.query_log_by_time(log, start, stop))

    def query_log_after(self, log: Ref, time: EntryTime | datetime, entry_id: EntryID | bytes) -> list[LogEntry]:
        return _run(self._c.query_log_after(log, time, entry_id))

    def log_status(self, log: Ref) -> int:
        return _run(self._c.log_status(log))

    # files

    def list_files(self, path: str = "") -> list[FileEntry]:
        return _run(self._c.list_files(path))

    def read_file(self, name: str) -> bytes:
        return _run(self._c.read_file(name))

    def download_file(
        self, name: str, dest: str | os.PathLike[str] | IO[bytes], *, on_chunk: Callable[[int], Any] | None = None
    ) -> int:
        """Chunks are written (and ``on_chunk`` called) on the facade's loop thread."""
        return _run(self._c.download_file(name, dest, on_chunk=on_chunk))

    def delete_file(self, name: str) -> None:
        _run(self._c.delete_file(name))

    def rename_file(self, current: str, new: str) -> None:
        _run(self._c.rename_file(current, new))

    # GOOSE control blocks

    def gocb_values(self, gocb: Ref) -> GoCBValues:
        return _run(self._c.gocb_values(gocb))

    def set_gocb_values(self, gocb: Ref, settings: GoCBSettings | None = None, **changes: Any) -> None:
        _run(self._c.set_gocb_values(gocb, settings, **changes))

    @property
    def reports_dropped(self) -> int:
        return self._c.reports_dropped

    def reports(self, *, queue_size: int = 1024) -> ReportStream:
        return ReportStream(_run(_call(lambda: self._c.reports(queue_size=queue_size))))

    def events(self, *, queue_size: int = 64) -> EventStream:
        return EventStream(_run(_call(lambda: self._c.events(queue_size=queue_size))))


async def _call(fn: Callable[[], T]) -> T:
    return fn()


class Server:
    """Blocking IEC 61850 server; see :class:`openiec61850.Server` for the semantics.

    >>> with Server.start(model, port=0) as server:                 # doctest: +SKIP
    ...     server.update("IED1LD0/GGIO1.Ind1.stVal", True)
    """

    def __init__(self, inner: _server.Server) -> None:
        """Internal; use :meth:`start`."""
        self._s = inner

    @classmethod
    def start(cls, model: _server.Model, host: str = "0.0.0.0", port: int = 102, **options: Any) -> Server:
        """Same keywords as :meth:`openiec61850.Server.start`."""
        return cls(_run(_server.Server.start(model, host, port, **options)))

    @property
    def aio(self) -> _server.Server:
        """The underlying asyncio server (bound to the facade's loop thread)."""
        return self._s

    def __enter__(self) -> Server:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
        self.wait_stopped()

    @property
    def model(self) -> _server.Model:
        return self._s.model

    def stop(self) -> None:
        self._s.stop()

    def wait_stopped(self, timeout: float | None = None) -> None:
        _run(self._s.wait_stopped(), timeout)

    @property
    def association_count(self) -> int:
        return self._s.association_count

    @property
    def local_endpoint(self) -> tuple[str, int]:
        return self._s.local_endpoint

    @property
    def port(self) -> int:
        return self._s.port

    def update(self, ref: Ref, value: Any, quality: Any = None, timestamp: Any = None) -> None:
        """Non-blocking; any thread."""
        self._s.update(ref, value, quality, timestamp)

    def update_many(self, items: Any) -> None:
        self._s.update_many(items)

    def read(self, ref: Ref) -> Any:
        return _run(self._s.read(ref))

    def select_active_setting_group(self, ld: str, sg: int) -> None:
        """Non-blocking; any thread."""
        self._s.select_active_setting_group(ld, sg)

    def read_setting_group(self, ref: Ref, sg: int) -> Any:
        return _run(self._s.read_setting_group(ref, sg))

    def goose_control(self, ref: Ref) -> _server.GooseControlState:
        return _run(self._s.goose_control(ref))

    def goose_controls(self) -> list[_server.GooseControlState]:
        return _run(self._s.goose_controls())
