"""Clients that stop reading and applications that outrun the server (binding parity of the limits
in the C++ tests/server/test_backpressure.cpp)."""

import asyncio
import socket
import threading

import pytest

import openiec61850 as iec
from openiec61850 import BasicType, FC, ModelBuilder, OptFlds, TrgOps
from openiec61850._errors import error_class_for

from conftest import FAST

URCB = "IED1LD0/LLN0.urcb01[RP]"
TEXT = "IED1LD0/GGIO1.Str1.stVal[ST]"
SETTING = "IED1LD0/GGIO1.Setting.setVal[SP]"


def model():
    b = ModelBuilder()
    ld = b.logical_device("IED1LD0")
    ggio = ld.logical_node("GGIO1")
    ggio.data_object("Str1").attribute(
        "stVal", FC.ST, BasicType.VISIBLE_STRING, size=255, triggers=TrgOps.DATA_CHANGE
    )
    ggio.data_object("Setting").attribute("setVal", FC.SP, BasicType.INT32)
    lln0 = ld.logical_node("LLN0")
    lln0.data_set("DS1", ["IED1LD0/GGIO1.Str1.stVal[ST]"])
    lln0.report_control(
        iec.ReportControl("urcb01", data_set="DS1", opt_flds=OptFlds.SEQUENCE_NUMBER, trg_ops=TrgOps.DATA_CHANGE)
    )
    return b.build()


class StallProxy:
    """Relays one connection; after ``stall()`` nothing more is read from the server."""

    def __init__(self, port):
        self._port = port
        self._flowing = asyncio.Event()
        self._flowing.set()
        self._tasks = []

    async def start(self):
        self._listener = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        return self._listener.sockets[0].getsockname()[1]

    def stall(self):
        self._flowing.clear()

    async def _serve(self, down_r, down_w):
        # A small receive window, so that the server's writes block as soon as its own send buffer
        # is full, wherever the receive buffers of the machine stand.
        up = socket.socket()
        up.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        up.setblocking(False)
        await asyncio.get_running_loop().sock_connect(up, ("127.0.0.1", self._port))
        up_r, up_w = await asyncio.open_connection(sock=up)
        self._writers = (down_w, up_w)
        self._tasks = [
            asyncio.ensure_future(self._relay(down_r, up_w, None)),
            asyncio.ensure_future(self._relay(up_r, down_w, self._flowing)),
        ]

    @staticmethod
    async def _relay(reader, writer, gate):
        while True:
            if gate is not None:
                await gate.wait()
            data = await reader.read(16384)
            if not data:
                break
            writer.write(data)
            await writer.drain()

    async def close(self):
        for t in self._tasks:
            t.cancel()
        for w in getattr(self, "_writers", ()):
            w.close()
        self._listener.close()


async def eventually(condition, timeout=30.0):
    end = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < end, "timed out"
        await asyncio.sleep(0.001)


async def load_until(s, condition, timeout=30.0):
    """Keeps the reports coming until ``condition``, for a time and not for a number of loops: how
    long the kernel buffers take to fill depends on the machine. Few updates are left pending, as
    the sender of the association shares the strand with them and otherwise crawls."""
    end = asyncio.get_running_loop().time() + timeout
    n = 0
    while not condition():
        assert asyncio.get_running_loop().time() < end, "timed out"
        n += 1
        if s.pending_updates < 16:
            s.update(TEXT, "x" * 200 + str(n))
        await asyncio.sleep(0)


async def test_a_client_that_stops_reading_is_aborted():
    iso = iec.ServerIsoParameters(max_output_bytes=256 * 1024, write_stall_timeout=0)
    async with await iec.Server.start(model(), "127.0.0.1", 0, iso=iso) as s:
        proxy = StallProxy(s.port)
        port = await proxy.start()
        healthy = await iec.Client.connect("127.0.0.1", s.port, **FAST)
        stalled = await iec.Client.connect("127.0.0.1", port, **FAST)
        await stalled.enable_reporting(URCB)
        proxy.stall()
        await load_until(s, lambda: s.association_count == 1)
        assert s.slow_peer_aborts == 1
        assert await healthy.read(TEXT)
        await healthy.close()
        stalled.abort()
        await proxy.close()


async def test_stall_timeout_without_reaching_the_limit():
    iso = iec.ServerIsoParameters(max_output_bytes=0, write_stall_timeout=0.1)
    async with await iec.Server.start(model(), "127.0.0.1", 0, iso=iso) as s:
        proxy = StallProxy(s.port)
        port = await proxy.start()
        stalled = await iec.Client.connect("127.0.0.1", port, **FAST)
        await stalled.enable_reporting(URCB)
        proxy.stall()
        await load_until(s, lambda: s.association_count == 0)
        assert s.slow_peer_aborts == 1
        stalled.abort()
        await proxy.close()


async def test_update_reports_overload_and_drops_nothing_it_took():
    entered = threading.Event()
    release = threading.Event()

    def on_write(association, ref, value):
        # Holds the strand, on the I/O thread.
        entered.set()
        release.wait(10.0)

    async with await iec.Server.start(model(), "127.0.0.1", 0, on_write=on_write, max_pending_updates=2) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            write = asyncio.ensure_future(c.write(SETTING, 1))
            await eventually(entered.is_set)
            s.update(TEXT, "first")
            s.update(TEXT, "second")
            assert s.pending_updates == 2
            with pytest.raises(iec.ServerOverloaded):
                s.update(TEXT, "third")
            with pytest.raises(iec.ServerOverloaded):
                s.update_many({TEXT: "fourth"})
            release.set()
            await write
            await eventually(lambda: s.pending_updates == 0)
            assert await s.read(TEXT) == "second"
            s.update(TEXT, "fifth")
            await eventually(lambda: s.pending_updates == 0)
            assert await s.read(TEXT) == "fifth"


async def test_limits_can_be_switched_off():
    iso = iec.ServerIsoParameters(max_output_bytes=0, write_stall_timeout=0)
    async with await iec.Server.start(model(), "127.0.0.1", 0, iso=iso, max_pending_updates=0) as s:
        client_iso = iec.IsoParameters(max_output_bytes=0, write_stall_timeout=0)
        async with await iec.Client.connect("127.0.0.1", s.port, iso=client_iso, **FAST) as c:
            for i in range(1000):
                s.update(TEXT, str(i))
            assert await c.read(SETTING) == 0
        assert s.slow_peer_aborts == 0


def test_error_classes():
    assert issubclass(iec.OutputLimitExceeded, iec.ConnectionLost)
    assert issubclass(iec.ServerOverloaded, iec.Iec61850Error)
    assert error_class_for("openiec61850", 10) is iec.OutputLimitExceeded
    assert error_class_for("openiec61850.server", 7) is iec.ServerOverloaded
