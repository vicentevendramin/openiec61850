import asyncio
import socket
import threading
import time

import pytest

import openiec61850 as iec
from openiec61850 import FC

from conftest import FAST

READ = 4
GET_NAME_LIST = 1


async def test_connect_and_close(server):
    async with await iec.Client.connect("127.0.0.1", server.port, **FAST) as c:
        assert c.state is iec.ConnectionState.ESTABLISHED
        info = c.association_info
        assert info.remote_endpoint == ("127.0.0.1", server.port)
        assert info.negotiated.max_serv_outstanding_calling >= 1
        assert info.peer_ap_title == iec.DEFAULT_AP_TITLE
        assert server.active_associations == 1
    assert c.state is iec.ConnectionState.CLOSED
    reason = await c.wait_closed()
    assert isinstance(reason, iec.ConnectionClosed)
    with pytest.raises(iec.NotConnected):
        await c.read("IED1LD0/MMXU1.TotW.mag.f[MX]")
    await c.close()  # no-op once closed


async def test_abort(client, server):
    client.abort()
    assert isinstance(await client.wait_closed(), iec.ConnectionClosed)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_connection_refused():
    with pytest.raises(iec.ConnectionRefused) as e:
        await iec.Client.connect("127.0.0.1", free_port(), **FAST)
    assert isinstance(e.value, ConnectionRefusedError)
    assert isinstance(e.value, iec.CommunicationError)


async def test_authentication():
    FakeServer = pytest.importorskip("openiec61850._testing").FakeServer

    s = FakeServer(password="secret")
    try:
        with pytest.raises(iec.AuthenticationFailed) as e:
            await iec.Client.connect("127.0.0.1", s.port, password="wrong", **FAST)
        assert isinstance(e.value, iec.AssociationRejected)
        c = await iec.Client.connect("127.0.0.1", s.port, password="secret", **FAST)
        await c.close()
    finally:
        s.close()


async def test_discovery(client, server):
    assert await client.server_directory() == ["IED1LD0", "IED1LD1"]
    assert await client.logical_device_directory("IED1LD0") == ["LLN0", "MMXU1", "XCBR1"]
    lln0 = await client.logical_node_directory("IED1LD0/LLN0")
    assert lln0.data_objects == ("Mod",)
    assert lln0.brcbs == ("brcb01",) and lln0.urcbs == ("urcb01",)
    assert lln0.data_sets == ("DS1",) and lln0.gocbs == () and not lln0.sgcb
    entries = await client.data_directory(iec.ObjectReference("IED1LD0/MMXU1.TotW"))
    assert entries[0] == iec.DataDirectoryEntry("mag", (FC.MX,))
    assert entries[-1] == iec.DataDirectoryEntry("db", (FC.CF,))
    assert await client.data_directory("IED1LD0/XCBR1") == [iec.DataDirectoryEntry("Pos", (FC.ST, FC.CF))]
    assert len(await client.name_list(iec.ObjectClass.DOMAIN)) == 2
    with pytest.raises(iec.ObjectNotFound):
        await client.logical_device_directory("NOPE")


async def test_name_list_continuations():
    FakeServer = pytest.importorskip("openiec61850._testing").FakeServer

    s = FakeServer(name_list_page=2)
    try:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            assert await c.logical_device_directory("IED1LD0") == ["LLN0", "MMXU1", "XCBR1"]
        assert s.requests(GET_NAME_LIST) > 10
    finally:
        s.close()


async def test_data_definition(client):
    totw = await client.data_definition("IED1LD0/MMXU1.TotW[MX]")
    assert totw.kind is iec.DefinitionKind.STRUCTURE and totw.fc is FC.MX
    assert [c.name for c in totw.children] == ["mag", "q", "t"]
    assert totw["q"].basic_type is iec.BasicType.QUALITY
    assert totw["t"].basic_type is iec.BasicType.TIMESTAMP
    assert totw["mag"]["f"].mms_type is iec.MmsType.FLOATING_POINT
    pos = await client.data_definition("IED1LD0/XCBR1.Pos")
    assert pos.fc is None and pos["stVal"].basic_type is iec.BasicType.DBPOS
    brcb = await client.data_definition("IED1LD0/LLN0.brcb01[BR]")
    assert brcb["RptID"].size == 129 and brcb["RptID"].variable_length
    with pytest.raises(iec.ObjectNotFound):
        await client.data_definition("IED1LD0/MMXU1.Nope[MX]")


async def test_read_conversions(client, server):
    assert await client.read("IED1LD0/MMXU1.TotW.mag.f[MX]") == 1.5
    totw = await client.read("IED1LD0/MMXU1.TotW[MX]")
    assert isinstance(totw, iec.Struct) and totw.names is None
    assert totw[0] == [1.5]
    assert isinstance(totw[1], iec.Quality) and totw[1].is_good
    assert isinstance(totw[2], iec.Timestamp)
    assert await client.read("IED1LD0/XCBR1.Pos.stVal[ST]") == iec.BitString("01")
    # With the definition known, values are named and typed.
    await client.data_definition("IED1LD0/XCBR1.Pos[ST]")
    assert await client.read("IED1LD0/XCBR1.Pos.stVal[ST]") is iec.DbPos.OFF
    await client.data_definition("IED1LD0/MMXU1.TotW[MX]")
    named = await client.read("IED1LD0/MMXU1.TotW[MX]")
    assert named["mag"]["f"] == 1.5 and named.names == ("mag", "q", "t")
    rcb = await client.read("IED1LD0/LLN0.brcb01[BR]")
    assert rcb[0] == "brcb01-id"


async def test_read_many(client):
    refs = ["IED1LD0/MMXU1.TotW.mag.f[MX]", "IED1LD0/MMXU1.Nope[MX]", "IED1LD0/XCBR1.Pos.q[ST]"]
    with pytest.raises(iec.ObjectNotFound) as e:
        await client.read_many(refs)
    assert e.value.index == 1
    values = await client.read_many(refs, return_exceptions=True)
    assert values[0] == 1.5
    assert isinstance(values[1], iec.ObjectNotFound)
    assert isinstance(values[2], iec.Quality)


async def test_write(client, server):
    # A plain float: the client fetches the definition to learn it is a FLOAT32.
    await client.write("IED1LD0/MMXU1.TotW.mag.f[MX]", 3.25)
    assert server.value("IED1LD0", "MMXU1$MX$TotW$mag$f") == (7, 3.25, False)
    # Explicit types need no definition.
    await client.write("IED1LD0/MMXU1.TotW.db[CF]", iec.UInt32(100))
    assert server.value("IED1LD0", "MMXU1$CF$TotW$db") == (6, 100)
    # A structure from a mapping, typed by the cached definition of an ancestor.
    await client.data_definition("IED1LD0/MMXU1.PhV[MX]")
    when = iec.Timestamp.from_raw(1_700_000_000, 1 << 23, 10)
    await client.write("IED1LD0/MMXU1.PhV.phsA[MX]", {"cVal": {"mag": {"f": 7}}, "q": iec.Quality(iec.Validity.INVALID), "t": when})
    assert server.value("IED1LD0", "MMXU1$MX$PhV$phsA$cVal$mag$f") == (7, 7.0, False)
    assert await client.read("IED1LD0/MMXU1.PhV.phsA.t[MX]") == when
    q = await client.read("IED1LD0/MMXU1.PhV.phsA.q[MX]")
    assert q.validity is iec.Validity.INVALID
    await client.write("IED1LD0/XCBR1.Pos.stVal[ST]", iec.DbPos.ON)
    assert await client.read("IED1LD0/XCBR1.Pos.stVal[ST]") == iec.DbPos.ON.to_bitstring()


async def test_write_errors(client):
    with pytest.raises(iec.TypeInconsistent) as e:
        await client.write("IED1LD0/MMXU1.TotW.db[CF]", iec.Int32(5))
    assert isinstance(e.value, iec.ServiceError)
    with pytest.raises(iec.ObjectNotFound):
        await client.write("IED1LD0/MMXU1.Nope[MX]", iec.Int32(5))
    with pytest.raises(TypeError):
        await client.write("IED1LD0/MMXU1.TotW.mag.f[MX]", "not a float")
    with pytest.raises(OverflowError):
        await client.write("IED1LD0/MMXU1.TotW.db[CF]", -1)


async def test_write_many(client, server):
    results = await client.write_many(
        [("IED1LD0/MMXU1.TotW.db[CF]", iec.UInt32(7)), ("IED1LD0/MMXU1.TotW.mag.f[MX]", iec.Int8(1))],
        return_exceptions=True,
    )
    assert results[0] is None and isinstance(results[1], iec.TypeInconsistent)
    assert server.value("IED1LD0", "MMXU1$CF$TotW$db") == (6, 7)
    await client.write_many({"IED1LD0/MMXU1.TotW.db[CF]": 9})
    assert server.value("IED1LD0", "MMXU1$CF$TotW$db") == (6, 9)


async def test_local_errors(client):
    with pytest.raises(iec.InvalidOperation):
        await client.read("IED1LD0/MMXU1.TotW")  # no FC
    with pytest.raises(iec.InvalidReference):
        await client.read("not a reference")


async def test_data_sets(client, server):
    ds = await client.data_set_directory("IED1LD0/LLN0.DS1")
    assert not ds.deletable
    assert [str(m) for m in ds.members] == [
        "IED1LD0/MMXU1.TotW[MX]",
        "IED1LD0/XCBR1.Pos.stVal[ST]",
        "IED1LD0/XCBR1.Pos.q[ST]",
        "IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]",
    ]
    values = await client.data_set_values("IED1LD0/LLN0.DS1")
    assert len(values) == 4 and values[3] == 0.0 and isinstance(values[2], iec.Quality)

    members = ["IED1LD0/XCBR1.Pos.stVal[ST]", "IED1LD0/MMXU1.TotW.db[CF]"]
    await client.create_data_set("IED1LD0/LLN0.DS2", members)
    with pytest.raises(iec.ObjectExists):
        await client.create_data_set("IED1LD0/LLN0.DS2", members)
    assert (await client.logical_node_directory("IED1LD0/LLN0")).data_sets == ("DS1", "DS2")
    assert (await client.data_set_directory("IED1LD0/LLN0.DS2")).deletable
    await client.delete_data_set("IED1LD0/LLN0.DS2")
    with pytest.raises(iec.NotDeleted):
        await client.delete_data_set("IED1LD0/LLN0.DS1")
    with pytest.raises(iec.ObjectNotFound):
        await client.create_data_set("IED1LD0/LLN0.DS3", ["IED1LD0/MMXU1.Nope[MX]"])

    await client.create_data_set("@tmp", members)
    assert (await client.data_set_directory("@tmp")).members == tuple(iec.ObjectReference(m) for m in members)
    # Plain values are typed from the data set's current values.
    assert await client.set_data_set_values("@tmp", [iec.DbPos.ON, 5]) == [None, None]
    assert await client.data_set_values("@tmp") == [iec.BitString("10"), 5]


async def test_timeout_and_cancellation(server):
    c = await iec.Client.connect("127.0.0.1", server.port, timeout=2.0, request_timeout=0.3)
    try:
        server.hold_requests(True)
        with pytest.raises(iec.Timeout) as e:
            await c.read("IED1LD0/MMXU1.TotW.mag.f[MX]")
        assert isinstance(e.value, TimeoutError)

        task = asyncio.ensure_future(c.read("IED1LD0/MMXU1.TotW.mag.f[MX]"))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # asyncio.wait_for cancels the native request too.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(c.read("IED1LD0/MMXU1.TotW.mag.f[MX]"), 0.05)
        server.hold_requests(False)
        # The cancelled requests freed their slots; the association keeps working.
        assert await c.read("IED1LD0/MMXU1.TotW.mag.f[MX]") == 1.5
        assert c.state is iec.ConnectionState.ESTABLISHED
    finally:
        c.abort()


async def test_concurrent_requests(client):
    refs = ["IED1LD0/MMXU1.TotW.mag.f[MX]"] * 50
    values = await asyncio.gather(*(client.read(r) for r in refs))
    assert values == [1.5] * 50


async def test_gil_released_while_waiting(server):
    c = await iec.Client.connect("127.0.0.1", server.port, timeout=2.0, request_timeout=0.5)
    counter = 0
    stop = threading.Event()

    def spin():
        nonlocal counter
        while not stop.is_set():
            counter += 1

    try:
        server.hold_requests(True)
        t = threading.Thread(target=spin)
        t.start()
        ticks = 0
        start = time.monotonic()
        read = asyncio.ensure_future(c.read("IED1LD0/MMXU1.TotW.mag.f[MX]"))
        while not read.done():
            await asyncio.sleep(0.01)
            ticks += 1
        elapsed = time.monotonic() - start
        stop.set()
        t.join()
        assert isinstance(read.exception(), iec.Timeout)
        assert elapsed >= 0.4
        # Both the event loop and another Python thread kept running during the slow request.
        assert ticks >= 10
        assert counter > 10_000
    finally:
        stop.set()
        c.abort()


async def test_connect_cancellation():
    # A listener that accepts TCP but never answers the COTP CR.
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    try:
        task = asyncio.ensure_future(iec.Client.connect("127.0.0.1", srv.getsockname()[1], timeout=5.0))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        srv.close()
