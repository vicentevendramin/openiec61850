import threading
import time

import pytest

import openiec61850 as iec
from openiec61850 import sync

from conftest import FAST


def test_sync_client(server):
    with sync.Client.connect("127.0.0.1", server.port, **FAST) as c:
        assert c.state is iec.ConnectionState.ESTABLISHED
        assert c.server_directory() == ["IED1LD0", "IED1LD1"]
        assert c.read("IED1LD0/MMXU1.TotW.mag.f[MX]") == 1.5
        c.write("IED1LD0/MMXU1.TotW.mag.f[MX]", 2.0)
        assert c.read_many(["IED1LD0/MMXU1.TotW.mag.f[MX]"]) == [2.0]
        assert len(c.data_set_values("IED1LD0/LLN0.DS1")) == 4
        with pytest.raises(iec.ObjectNotFound):
            c.read("IED1LD0/MMXU1.Nope[MX]")

        with c.enable_reporting("IED1LD0/LLN0.urcb01[RP]", gi=True) as sub:
            assert len(sub.get(timeout=2).entries) == 4
            server.update("MMXU1$MX$TotW$mag$f", (7, 5.0, False))
            assert next(sub).entries[0].value[0] == [5.0]
            with pytest.raises(TimeoutError):
                sub.get(timeout=0.05)
        assert not server.rcb_enabled("urcb01")

        got = threading.Event()
        c.enable_reporting("IED1LD0/LLN0.urcb01[RP]", gi=True, callback=lambda r: got.set())
        assert got.wait(2)
    assert c.state is iec.ConnectionState.CLOSED


def test_sync_events(server):
    c = sync.Client.connect("127.0.0.1", server.port, recovery=iec.Recovery(backoff=[0.05]), **FAST)
    events = c.events()
    server.drop_connections()
    assert events.get(timeout=2).kind is iec.EventKind.LOST
    c.close()


def test_sync_call_releases_the_gil(server):
    c = sync.Client.connect("127.0.0.1", server.port, timeout=2.0, request_timeout=0.5)
    counter = 0
    stop = threading.Event()

    def spin():
        nonlocal counter
        while not stop.is_set():
            counter += 1

    t = threading.Thread(target=spin)
    try:
        server.hold_requests(True)
        t.start()
        start = time.monotonic()
        with pytest.raises(iec.Timeout):
            c.read("IED1LD0/MMXU1.TotW.mag.f[MX]")
        assert time.monotonic() - start >= 0.4
        stop.set()
        t.join()
        assert counter > 10_000
    finally:
        stop.set()
        c.abort()
