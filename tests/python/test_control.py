import asyncio
from datetime import datetime, timezone

import pytest

import openiec61850 as iec
from openiec61850 import sync

from conftest import FAST

WRITE = 5


async def test_direct_with_normal_security(client, server):
    ctl = await client.control("IED1LD1/GGIO1.SPCSO1")
    assert ctl.ctl_model is iec.CtlModel.DIRECT_WITH_NORMAL_SECURITY
    assert str(ctl.reference) == "IED1LD1/GGIO1.SPCSO1"
    assert ctl.sbo_timeout is None
    assert ctl.has_oper_time is False
    assert ctl.last_error is None

    await ctl.operate(True, test=True, origin=iec.Originator(iec.OrCat.STATION_CONTROL, b"hmi"))
    assert server.value("IED1LD1", "GGIO1$ST$SPCSO1$stVal") == (3, True)
    assert server.operations("GGIO1.SPCSO1") == 1
    req = server.last_control_request("GGIO1.SPCSO1")
    # { ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }
    assert req[1][1] == (2, [(5, 2), (9, b"hmi")])
    assert req[1][4] == (3, True)
    assert ctl.ctl_num == 0

    await ctl.operate(False)
    assert ctl.ctl_num == 1
    assert server.value("IED1LD1", "GGIO1$ST$SPCSO1$stVal") == (3, False)

    # Services the ctlModel does not have.
    with pytest.raises(iec.ControlModelMismatch):
        await ctl.select()
    with pytest.raises(iec.ControlError):
        await ctl.cancel()


async def test_interlock_blocked(client, server):
    ctl = await client.control("IED1LD1/GGIO1.SPCSO1")
    assert server.set_interlocked("GGIO1.SPCSO1", True)
    with pytest.raises(iec.ControlRefused) as info:
        await ctl.operate(True, interlock_check=True, ctl_num=42)
    e = info.value
    assert isinstance(e, iec.ControlError) and isinstance(e, iec.ServiceError)
    assert e.add_cause is iec.AddCause.BLOCKED_BY_INTERLOCKING
    assert e.last_appl_error is not None
    assert e.last_appl_error.add_cause is iec.AddCause.BLOCKED_BY_INTERLOCKING
    assert e.last_appl_error.control_object == "IED1LD1/GGIO1$CO$SPCSO1$Oper"
    assert e.last_appl_error.ctl_num == 42
    assert e.last_appl_error.error is iec.ControlErrorCode.UNKNOWN
    assert e.category == "openiec61850.control"
    assert ctl.last_error == e.last_appl_error
    # Without the check the server accepts it.
    await ctl.operate(True)

    assert server.set_synchrocheck_blocked("GGIO1.SPCSO1", True)
    with pytest.raises(iec.ControlRefused) as info:
        await client.operate("IED1LD1/GGIO1.SPCSO1", True, synchro_check=True)
    assert info.value.add_cause is iec.AddCause.BLOCKED_BY_SYNCHROCHECK


async def test_sbo_with_normal_security(client, server):
    ctl = await client.control("IED1LD1/GGIO1.SPCSO2[CO]")
    assert ctl.ctl_model is iec.CtlModel.SBO_WITH_NORMAL_SECURITY
    assert ctl.sbo_timeout == 30.0

    # Operate without a selection is refused.
    with pytest.raises(iec.ControlRefused) as info:
        await ctl.operate(True)
    assert info.value.add_cause is iec.AddCause.OBJECT_NOT_SELECTED

    await ctl.select()
    assert ctl.selected
    assert server.selected("GGIO1.SPCSO2")
    await ctl.operate(True)
    assert not ctl.selected
    assert server.value("IED1LD1", "GGIO1$ST$SPCSO2$stVal") == (3, True)

    # Cancel ends a selection.
    await ctl.select()
    await ctl.cancel()
    assert not ctl.selected
    assert not server.selected("GGIO1.SPCSO2")
    assert server.cancellations("GGIO1.SPCSO2") == 1

    # One-shot operate selects first.
    await client.operate("IED1LD1/GGIO1.SPCSO2", False)
    assert server.value("IED1LD1", "GGIO1$ST$SPCSO2$stVal") == (3, False)


async def test_select_timeout(client, server):
    assert server.set_value("IED1LD1", "GGIO1$CF$SPCSO2$sboTimeout", (6, 50))
    ctl = await client.control("IED1LD1/GGIO1.SPCSO2")
    assert ctl.sbo_timeout == 0.05
    await ctl.select()
    await asyncio.sleep(0.2)
    with pytest.raises(iec.ControlRefused) as info:
        await ctl.operate(True)
    assert info.value.add_cause is iec.AddCause.OBJECT_NOT_SELECTED
    # The refused sequence stays open on the client; a new selection works.
    await ctl.select()
    await ctl.operate(True)


async def test_direct_with_enhanced_security(client, server):
    ctl = await client.control("IED1LD1/GGIO1.SPCSO3")
    assert ctl.ctl_model is iec.CtlModel.DIRECT_WITH_ENHANCED_SECURITY
    assert ctl.has_oper_time is True
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    await ctl.operate(True, oper_time=iec.Timestamp(when))
    assert server.operations("GGIO1.SPCSO3") == 1
    req = server.last_control_request("GGIO1.SPCSO3")
    assert req[1][1][0] == 17  # operTm utc-time
    assert iec.Timestamp.from_raw(*req[1][1][1:]).datetime == when

    # Negative termination.
    assert server.set_command_termination("GGIO1.SPCSO3", "negative", int(iec.AddCause.ABORTION_BY_TRIP))
    with pytest.raises(iec.ControlRefused) as info:
        await ctl.operate(False)
    assert info.value.add_cause is iec.AddCause.ABORTION_BY_TRIP
    assert ctl.last_error.add_cause is iec.AddCause.ABORTION_BY_TRIP

    # No termination at all.
    assert server.set_command_termination("GGIO1.SPCSO3", "none")
    with pytest.raises(iec.TerminationTimeout) as t:
        await ctl.operate(True, termination_timeout=0.1)
    assert isinstance(t.value, iec.Timeout) and isinstance(t.value, TimeoutError)


async def test_sbo_with_enhanced_security(client, server):
    ctl = await client.control("IED1LD1/XCBR1.Pos")
    assert ctl.ctl_model is iec.CtlModel.SBO_WITH_ENHANCED_SECURITY
    assert repr(ctl) == "Control('IED1LD1/XCBR1.Pos', SBO_WITH_ENHANCED_SECURITY)"

    await ctl.select_with_value(True)
    assert ctl.selected
    await ctl.operate(True)
    assert server.operations("XCBR1.Pos") == 1
    assert server.value("IED1LD1", "XCBR1$ST$Pos$stVal")[0] == 4  # Dbpos bit-string

    # Oper with a value other than the SBOw one.
    await ctl.select_with_value(False)
    with pytest.raises(iec.ControlRefused) as info:
        await ctl.operate(True)
    assert info.value.add_cause is iec.AddCause.INCONSISTENT_PARAMETERS
    await ctl.cancel()
    assert not server.selected("XCBR1.Pos")

    # Already selected by another client.
    other = await iec.Client.connect("127.0.0.1", server.port, **FAST)
    try:
        await ctl.select_with_value(True)
        ctl2 = await other.control("IED1LD1/XCBR1.Pos")
        with pytest.raises(iec.ControlRefused) as info:
            await ctl2.select_with_value(True)
        assert info.value.add_cause is iec.AddCause.OBJECT_ALREADY_SELECTED
        await ctl.cancel()
    finally:
        await other.close()

    # One-shot operate: SBOw + Oper + termination.
    await client.operate("IED1LD1/XCBR1.Pos", False)
    assert server.operations("XCBR1.Pos") == 2

    # Select is not available in this model.
    with pytest.raises(iec.ControlModelMismatch):
        await ctl.select()


async def test_control_errors(client, server):
    with pytest.raises(iec.ObjectNotFound):
        await client.control("IED1LD1/GGIO1.SPCSO9")
    with pytest.raises(iec.InvalidOperation):
        await client.control("IED1LD1/GGIO1")
    # A forced ctlModel without reading it.
    ctl = await client.control("IED1LD1/GGIO1.SPCSO1", ctl_model=iec.CtlModel.DIRECT_WITH_NORMAL_SECURITY,
                               read_structure=False)
    await ctl.operate(True)
    with pytest.raises(ValueError):
        await ctl.operate(True, ctl_num=300)


def test_sync_control(server):
    with sync.Client.connect("127.0.0.1", server.port, **FAST) as c:
        ctl = c.control("IED1LD1/GGIO1.SPCSO2")
        assert ctl.ctl_model is iec.CtlModel.SBO_WITH_NORMAL_SECURITY
        ctl.select()
        assert ctl.selected
        ctl.operate(True)
        c.operate("IED1LD1/GGIO1.SPCSO1", True)
        assert server.set_interlocked("GGIO1.SPCSO1", True)
        with pytest.raises(iec.ControlRefused) as info:
            c.operate("IED1LD1/GGIO1.SPCSO1", False, interlock_check=True)
        assert info.value.add_cause is iec.AddCause.BLOCKED_BY_INTERLOCKING
        assert ctl.last_error is None
