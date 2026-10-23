import asyncio

import pytest

import openiec61850 as iec
from openiec61850 import OptFlds, TrgOps

from conftest import FAST

BRCB = "IED1LD0/LLN0.brcb01[BR]"
URCB = "IED1LD0/LLN0.urcb01[RP]"
FIELDS = OptFlds.SEQUENCE_NUMBER | OptFlds.REASON_FOR_INCLUSION | OptFlds.DATA_SET_NAME | OptFlds.CONF_REVISION


def f32(v):
    return (7, v, False)


async def next_report(sub, timeout=2.0):
    return await asyncio.wait_for(sub.__anext__(), timeout)


async def test_rcb_values(client):
    b = await client.rcb_values(BRCB)
    assert b.rpt_id == "brcb01-id" and b.rpt_ena is False
    assert b.dat_set == "IED1LD0/LLN0$DS1" and b.data_set == "IED1LD0/LLN0.DS1"
    assert b.conf_rev == 1 and TrgOps.DATA_CHANGE in b.trg_ops
    assert b.entry_id.is_zero and isinstance(b.time_of_entry, iec.EntryTime)
    u = await client.rcb_values(URCB)
    assert u.resv is False and u.entry_id is None


async def test_set_rcb_values_and_reservation(client, server):
    await client.set_rcb_values(URCB, rpt_id="u1", intg_pd=1000, trg_ops=TrgOps.INTEGRITY)
    assert server.value("IED1LD0", "LLN0$RP$urcb01$RptID") == (10, "u1")
    assert server.value("IED1LD0", "LLN0$RP$urcb01$Resv") == (3, True)
    async with await iec.Client.connect("127.0.0.1", server.port, **FAST) as other:
        with pytest.raises(iec.AccessDenied):
            await other.set_rcb_values(URCB, iec.RcbSettings(rpt_id="mine"))
    with pytest.raises(iec.ObjectNotFound):
        await client.rcb_values("IED1LD0/LLN0.brcb99[BR]")


async def test_urcb_async_iteration(client, server):
    sub = await client.enable_reporting(URCB, opt_flds=FIELDS, gi=True)
    assert sub.values.dat_set == "IED1LD0/LLN0$DS1"
    assert server.rcb_enabled("urcb01")
    gi = await next_report(sub)
    assert gi.rcb == URCB and gi.seq_num == 0 and gi.conf_rev == 1
    assert gi.data_set == "IED1LD0/LLN0$DS1"
    assert [str(e.reference) for e in gi.entries][0] == "IED1LD0/MMXU1.TotW[MX]"
    assert all(e.reason == TrgOps.GENERAL_INTERROGATION for e in gi.entries)
    assert gi["IED1LD0/MMXU1.TotW[MX]"][0] == [1.5]

    assert server.update("MMXU1$MX$TotW$mag$f", f32(2.5))
    change = await next_report(sub)
    assert change.seq_num == 1 and change.inclusion == (True, False, False, False)
    assert change.entries[0].value[0] == [2.5] and change.entries[0].reason == TrgOps.DATA_CHANGE

    await sub.trigger_gi()
    assert len((await next_report(sub)).entries) == 4

    await sub.disable()
    assert not server.rcb_enabled("urcb01")
    with pytest.raises(StopAsyncIteration):
        await next_report(sub)


async def test_async_for_and_context_manager(client, server):
    received = []
    async with await client.enable_reporting(URCB, opt_flds=FIELDS, gi=True) as sub:
        async for report in sub:
            received.append(report)
            if len(received) == 1:
                server.update("MMXU1$MX$TotW$mag$f", f32(4.0))
            else:
                break
    assert [r.seq_num for r in received] == [0, 1]
    assert not server.rcb_enabled("urcb01")


async def test_callback(client, server):
    got = []
    done = asyncio.Event()

    async def on_report(r):
        got.append(r)
        if len(got) == 2:
            done.set()

    await client.enable_reporting(BRCB, opt_flds=FIELDS | OptFlds.ENTRY_ID, gi=True, callback=on_report)
    server.update("MMXU1$MX$TotW$mag$f", f32(3.0))
    await asyncio.wait_for(done.wait(), 2)
    assert got[0].entry_id is not None and got[1].entries[0].value[0] == [3.0]
    assert client.last_entry_id(BRCB) == got[1].entry_id
    await client.disable_reporting(BRCB)


async def test_brcb_resume_after_entry_id(client, server):
    sub = await client.enable_reporting(BRCB, opt_flds=FIELDS | OptFlds.ENTRY_ID, purge_buffer=True)
    for v in (1.0, 2.0, 3.0):
        server.update("MMXU1$MX$TotW$mag$f", f32(v))
    reports = [await next_report(sub) for _ in range(3)]
    await sub.disable()
    assert server.buffered_entries("brcb01") == 3
    resumed = await client.enable_reporting(BRCB, opt_flds=FIELDS | OptFlds.ENTRY_ID, entry_id=reports[0].entry_id)
    again = [await next_report(resumed) for _ in range(2)]
    assert [r.entry_id for r in again] == [r.entry_id for r in reports[1:]]


async def test_reports_stream(client, server):
    stream = client.reports()
    server.send_report([(10, "unknown"), (4, b"\x00\x00", 10), (4, b"\x80", 1), (3, True)])
    r = await asyncio.wait_for(stream.get(), 2)
    assert r.rpt_id == "unknown" and r.rcb is None and r.entries[0].value is True
    stream.close()


async def test_loss_without_recovery_ends_with_error(client, server):
    sub = await client.enable_reporting(URCB, opt_flds=FIELDS)
    events = client.events()
    server.drop_connections()
    with pytest.raises(iec.CommunicationError):
        await next_report(sub)
    event = await asyncio.wait_for(events.get(), 2)
    assert event.kind is iec.EventKind.LOST and isinstance(event.error, iec.CommunicationError)
    assert isinstance(await client.wait_closed(), iec.CommunicationError)


async def test_recovery_events_and_reenabled_reports(server):
    c = await iec.Client.connect("127.0.0.1", server.port, recovery=iec.Recovery(backoff=[0.05]), **FAST)
    try:
        events = c.events()
        sub = await c.enable_reporting(URCB, opt_flds=FIELDS)
        server.drop_connections()
        kinds = []
        while not kinds or kinds[-1] is not iec.EventKind.RESTORED:
            kinds.append((await asyncio.wait_for(events.get(), 3)).kind)
        assert kinds[:2] == [iec.EventKind.LOST, iec.EventKind.RECONNECTING]
        assert c.state is iec.ConnectionState.ESTABLISHED
        assert server.associations_accepted == 2 and server.rcb_enabled("urcb01")
        server.update("MMXU1$MX$TotW$mag$f", f32(9.0))
        r = await next_report(sub, 3)
        assert r.entries[0].value[0] == [9.0]
        await c.close()
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(events.get(), 2)
        with pytest.raises(StopAsyncIteration):
            await next_report(sub)
    finally:
        c.abort()


async def test_recovery_failed(server):
    c = await iec.Client.connect(
        "127.0.0.1", server.port, recovery=iec.Recovery(backoff=[0.01], max_attempts=2), **FAST
    )
    events = c.events()
    server.stop()
    kinds = []
    async for e in events:
        kinds.append(e.kind)
    assert kinds[0] is iec.EventKind.LOST and kinds[-1] is iec.EventKind.FAILED
    assert isinstance(await c.wait_closed(), iec.RecoveryFailed)
