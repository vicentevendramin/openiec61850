"""Python server <-> Python client, end to end over loopback."""

import asyncio
import threading
from pathlib import Path

import pytest

import openiec61850 as iec
from openiec61850 import FC, AddCause, BasicType as B, OptFlds, TrgOps, sync
from openiec61850._server import ControlAction

from conftest import FAST

SCL_DATA = Path(__file__).resolve().parents[1] / "scl" / "data"
LD = "IED1LD0"
FIELDS = (
    OptFlds.SEQUENCE_NUMBER
    | OptFlds.REASON_FOR_INCLUSION
    | OptFlds.DATA_SET_NAME
    | OptFlds.DATA_REFERENCE
    | OptFlds.CONF_REVISION
)
TRG = TrgOps.DATA_CHANGE | TrgOps.QUALITY_CHANGE | TrgOps.GENERAL_INTERROGATION


def add_controllable(ln, name, ctl_model):
    pos = ln.data_object(name)
    pos.attribute("stVal", FC.ST, B.BOOLEAN, triggers=TrgOps.DATA_CHANGE)
    pos.attribute("q", FC.ST, B.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
    pos.attribute("t", FC.ST, B.TIMESTAMP)
    pos.attribute("ctlModel", FC.CF, B.ENUMERATED, value=int(ctl_model))
    sbo = ctl_model in (iec.CtlModel.SBO_WITH_NORMAL_SECURITY, iec.CtlModel.SBO_WITH_ENHANCED_SECURITY)
    if sbo:
        pos.attribute("sboTimeout", FC.CF, B.INT32U, value=2000)
    if ctl_model == iec.CtlModel.SBO_WITH_NORMAL_SECURITY:
        pos.attribute("SBO", FC.CO, B.OBJECT_REFERENCE)

    def oper(svc):
        o = pos.structure(svc, FC.CO)
        o.attribute("ctlVal", B.BOOLEAN)
        origin = o.structure("origin")
        origin.attribute("orCat", B.ENUMERATED)
        origin.attribute("orIdent", B.OCTET_STRING, size=64)
        o.attribute("ctlNum", B.INT8U)
        o.attribute("T", B.TIMESTAMP)
        o.attribute("Test", B.BOOLEAN)
        if svc != "Cancel":
            o.attribute("Check", B.CHECK)

    if ctl_model == iec.CtlModel.SBO_WITH_ENHANCED_SECURITY:
        oper("SBOw")
    oper("Oper")
    if sbo or ctl_model == iec.CtlModel.DIRECT_WITH_ENHANCED_SECURITY:
        oper("Cancel")


def make_model():
    b = iec.ModelBuilder()
    ld = b.logical_device(LD)
    lln0 = ld.logical_node("LLN0")
    mod = lln0.data_object("Mod")
    mod.attribute("stVal", FC.ST, B.ENUMERATED, triggers=TrgOps.DATA_CHANGE, value=1)
    mod.attribute("q", FC.ST, B.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
    mod.attribute("t", FC.ST, B.TIMESTAMP)
    lln0.data_object("NamPlt").attribute("vendor", FC.DC, B.VISIBLE_STRING, size=64, value="acme")

    mmxu = ld.logical_node("MMXU1")
    totw = mmxu.data_object("TotW")
    totw.structure("mag", FC.MX).attribute("f", B.FLOAT32, triggers=TrgOps.DATA_CHANGE, value=1.5)
    totw.attribute("q", FC.MX, B.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
    totw.attribute("t", FC.MX, B.TIMESTAMP)
    totw.attribute("db", FC.CF, B.INT32U, value=100)

    ggio = ld.logical_node("GGIO1")
    for i in (1, 2):
        ind = ggio.data_object(f"Ind{i}")
        ind.attribute("stVal", FC.ST, B.BOOLEAN, triggers=TrgOps.DATA_CHANGE)
        ind.attribute("q", FC.ST, B.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
        ind.attribute("t", FC.ST, B.TIMESTAMP)
    ggio.data_object("Set").attribute("setVal", FC.SP, B.INT32, value=7)
    ggio.data_object("Arr").attribute("vals", FC.SP, B.INT32, count=4, value=[1, 2, 3, 4])

    add_controllable(ld.logical_node("XCBR1"), "Pos", iec.CtlModel.DIRECT_WITH_NORMAL_SECURITY)
    add_controllable(ld.logical_node("CSWI1"), "Pos", iec.CtlModel.SBO_WITH_NORMAL_SECURITY)
    add_controllable(ld.logical_node("CSWI2"), "Pos", iec.CtlModel.DIRECT_WITH_ENHANCED_SECURITY)
    add_controllable(ld.logical_node("CSWI3"), "Pos", iec.CtlModel.SBO_WITH_ENHANCED_SECURITY)

    lln0.data_set("DS1", [f"{LD}/MMXU1.TotW[MX]", f"{LD}/GGIO1.Ind1[ST]", f"{LD}/GGIO1.Ind2.stVal[ST]"])
    lln0.report_control(iec.ReportControl("brcb01", buffered=True, rpt_id="b1", data_set="DS1",
                                          opt_flds=FIELDS, trg_ops=TRG))
    lln0.report_control(iec.ReportControl("urcb01", rpt_id="u1", data_set="DS1", opt_flds=FIELDS, trg_ops=TRG))
    return b.build()


MODEL = make_model()


@pytest.fixture
async def srv():
    s = await iec.Server.start(MODEL, "127.0.0.1", 0, handshake_timeout=2.0, association_timeout=2.0)
    yield s
    s.stop()
    await s.wait_stopped()


@pytest.fixture
async def cli(srv):
    async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
        yield c


async def started(**hooks):
    return await iec.Server.start(MODEL, "127.0.0.1", 0, handshake_timeout=2.0, **hooks)


# --- model


def test_model_view():
    m = MODEL
    assert m.edition is iec.Edition.ED2 and m.diagnostics == ()
    assert [n.name for n in m.logical_devices] == [LD]
    lns = [n.name for n in m.logical_devices[0].children]
    assert lns[:3] == ["LLN0", "MMXU1", "GGIO1"]
    f = m.find(f"{LD}/MMXU1.TotW.mag.f")
    assert f is not None and f.kind is iec.NodeKind.DATA_ATTRIBUTE
    assert f.fc is FC.MX and f.basic_type is B.FLOAT32 and f.triggers == TrgOps.DATA_CHANGE
    assert f.reference == f"{LD}/MMXU1.TotW.mag.f" and f.initial_value == 1.5
    assert f.parent.name == "mag" and f.parent.parent.kind is iec.NodeKind.DATA_OBJECT
    assert m.find(f"{LD}/GGIO1.Arr.vals").initial_value == [1, 2, 3, 4]
    assert m.find(f"{LD}/NOPE1") is None

    d = m.type_of(f"{LD}/MMXU1.TotW[MX]")
    assert [c.name for c in d.children] == ["mag", "q", "t"]
    assert d["q"].basic_type is B.QUALITY
    assert m.type_of(f"{LD}/GGIO1.Arr.vals(2)[SP]").mms_type is iec.MmsType.INTEGER
    assert m.type_of(f"{LD}/GGIO1.Arr.vals").array_size == 4
    with pytest.raises(iec.ObjectNotFound):
        m.type_of(f"{LD}/GGIO1.Nope[ST]")

    (ds,) = m.data_sets
    assert str(ds.reference) == f"{LD}/LLN0.DS1" and len(ds.members) == 3
    rcbs = {rc.name: rc for _, rc in m.report_controls}
    assert rcbs["brcb01"].buffered and rcbs["urcb01"].trg_ops == TRG and rcbs["urcb01"].data_set == "DS1"


def test_builder_errors():
    b = iec.ModelBuilder()
    ln = b.logical_device("LD1").logical_node("GGIO1")
    ln.data_object("Ind1").attribute("stVal", FC.ST, B.BOOLEAN)
    with pytest.raises(iec.ObjectExists):
        ln.data_object("Ind1")
    with pytest.raises(iec.Iec61850Error):  # the builder stays failed
        ln.data_object("Ind2")

    b = iec.ModelBuilder()
    ln = b.logical_device("LD1").logical_node("GGIO1")
    with pytest.raises(OverflowError):
        ln.data_object("Ind1").attribute("v", FC.ST, B.INT8, value=1000)
    b = iec.ModelBuilder()
    ln = b.logical_device("LD1").logical_node("GGIO1")
    ln.data_object("Ind1").attribute("stVal", FC.ST, B.BOOLEAN)
    ln.data_set("DS", ["LD1/GGIO1.Missing[ST]"])
    with pytest.raises(iec.Iec61850Error):
        b.build()
    with pytest.raises(ValueError):
        b.build()


def test_scl_model():
    m = iec.Model.from_scl(SCL_DATA / "ed2_bay.cid")
    assert [n.name for n in m.logical_devices] == ["Bay1Prot"]
    assert all(isinstance(d, iec.SclDiagnostic) for d in m.diagnostics)
    assert not [d for d in m.diagnostics if d.level == "error"]
    assert m.find("Bay1Prot/PTOC1.StrVal.setMag.f[SG]").initial_value == 100.0
    m2 = iec.Model.from_scl(SCL_DATA / "ed2_bay.cid", setting_group=2)
    assert m2.find("Bay1Prot/PTOC1.StrVal.setMag.f[SG]").initial_value == 150.5
    names = {rc.name for _, rc in m.report_controls}
    assert {"brcbMeas01", "brcbMeas02", "urcbStatus"} <= names

    text = (SCL_DATA / "ed2_bay.cid").read_text()
    assert [n.name for n in iec.Model.from_scl(text).logical_devices] == ["Bay1Prot"]

    with pytest.raises(iec.SclError) as info:
        iec.Model.from_scl("<SCL><broken")
    assert info.value.diagnostics and info.value.diagnostics[0].code == "xml_syntax"
    with pytest.raises(iec.SclError):
        iec.Model.from_scl(SCL_DATA / "ed2_bay.cid", ied="NOPE")


async def test_scl_model_served():
    m = iec.Model.from_scl(SCL_DATA / "ed2_bay.cid")
    async with await iec.Server.start(m, "127.0.0.1", 0) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            assert await c.server_directory() == ["Bay1Prot"]
            assert await c.read("Bay1Prot/PTOC1.StrVal.setMag.f[SG]") == 100.0
            d = await c.data_set_directory("Bay1Prot/LLN0.Status")
            assert len(d.members) == 2
            s.update("Bay1Prot/MMXU1.Hz.mag.f", 50.0)
            assert await c.read("Bay1Prot/MMXU1.Hz.mag.f[MX]") == 50.0


# --- lifecycle


async def test_start_stop():
    s = await iec.Server.start(MODEL, "127.0.0.1", 0)
    host, port = s.local_endpoint
    assert host == "127.0.0.1" and port > 0 and s.port == port
    assert s.association_count == 0
    c = await iec.Client.connect("127.0.0.1", port, **FAST)
    assert s.association_count == 1
    s.stop()
    await asyncio.wait_for(s.wait_stopped(), 5)
    assert s.association_count == 0
    await c.wait_closed()
    with pytest.raises(iec.ServerStopped):
        s.update(f"{LD}/GGIO1.Ind1.stVal", True)
    # Windows retries for about two seconds before it reports the refusal.
    with pytest.raises(iec.CommunicationError):
        await iec.Client.connect("127.0.0.1", port, **{**FAST, "timeout": 10.0})
    s.stop()  # idempotent

    async with await iec.Server.start(MODEL, "127.0.0.1", 0, max_associations=1) as s2:
        async with await iec.Client.connect("127.0.0.1", s2.port, **FAST):
            with pytest.raises(iec.CommunicationError):
                await iec.Client.connect("127.0.0.1", s2.port, **FAST)


async def test_address_in_use(srv):
    with pytest.raises(iec.CommunicationError):
        await iec.Server.start(MODEL, "127.0.0.1", srv.port)
    with pytest.raises(ValueError):
        await iec.Server.start(MODEL, "not an address", 0)


async def test_password_and_authorize():
    seen = []

    def authorize(req):
        seen.append(req)
        return req.calling_ae_qualifier is not None

    async with await iec.Server.start(MODEL, "127.0.0.1", 0, password="secret", authorize=authorize) as s:
        with pytest.raises(iec.AuthenticationFailed):
            await iec.Client.connect("127.0.0.1", s.port, **FAST)
        async with await iec.Client.connect("127.0.0.1", s.port, password="secret", **FAST):
            pass
        with pytest.raises(iec.AuthenticationFailed):
            await iec.Client.connect("127.0.0.1", s.port, password="secret", ae_qualifier=None, **FAST)
    assert seen and seen[0].password == "secret" and seen[0].remote[0] == "127.0.0.1"


# --- discovery, reads, updates


async def test_discovery(cli):
    assert await cli.server_directory() == [LD]
    assert sorted(await cli.logical_device_directory(LD)) == ["CSWI1", "CSWI2", "CSWI3", "GGIO1", "LLN0", "MMXU1", "XCBR1"]
    d = await cli.logical_node_directory(f"{LD}/LLN0")
    assert list(d.data_sets) == ["DS1"]
    assert list(d.brcbs) == ["brcb01"] and list(d.urcbs) == ["urcb01"]
    dd = await cli.data_definition(f"{LD}/MMXU1.TotW[MX]")
    assert [c.name for c in dd.children] == ["mag", "q", "t"]
    ident = await cli.read(f"{LD}/LLN0.NamPlt.vendor[DC]")
    assert ident == "acme"


async def test_update_and_read(srv, cli):
    ref = f"{LD}/GGIO1.Ind1.stVal"
    assert await cli.read(ref + "[ST]") is False
    ts = iec.Timestamp.now()
    srv.update(ref, True, quality=iec.Quality(validity=iec.Validity.QUESTIONABLE), timestamp=ts)
    # The server's read names the components from the model; the client's from a data definition.
    v = await srv.read(f"{LD}/GGIO1.Ind1[ST]")
    assert v["stVal"] is True and v["q"].validity is iec.Validity.QUESTIONABLE
    assert abs(v["t"].nanoseconds - ts.nanoseconds) < 1000
    stval, q, _ = await cli.read(f"{LD}/GGIO1.Ind1[ST]")
    assert stval is True and q.validity is iec.Validity.QUESTIONABLE

    srv.update(f"{LD}/MMXU1.TotW.mag[MX]", {"f": 3.25})
    srv.update(f"{LD}/GGIO1.Arr.vals(1)[SP]", 20)
    srv.update_many([(f"{LD}/MMXU1.TotW.mag.f", 4.5), (f"{LD}/GGIO1.Ind2.stVal", True, iec.Quality())])
    srv.update_many({f"{LD}/GGIO1.Set.setVal": -3})
    assert await cli.read(f"{LD}/MMXU1.TotW.mag.f[MX]") == 4.5
    assert await cli.read(f"{LD}/GGIO1.Arr.vals[SP]") == [1, 20, 3, 4]
    assert await srv.read(f"{LD}/GGIO1.Set.setVal[SP]") == -3
    whole = await srv.read(f"{LD}/GGIO1")
    assert len(whole) == 2  # ST, SP

    with pytest.raises(iec.ObjectNotFound):
        srv.update(f"{LD}/GGIO1.Nope.stVal", True)
    with pytest.raises(TypeError):
        srv.update(f"{LD}/GGIO1.Ind1.stVal", "yes")
    with pytest.raises(OverflowError):
        srv.update(f"{LD}/GGIO1.Set.setVal", 1 << 40)
    with pytest.raises(iec.InvalidReference):
        srv.update("not a reference", 1)
    with pytest.raises(iec.ObjectNotFound):
        await srv.read(f"{LD}/GGIO1.Nope[ST]")


# --- writes


async def test_on_write():
    writes = []

    def on_write(association, ref, value):
        writes.append((association, str(ref), value))
        if value == 13:
            return iec.DataAccessError.OBJECT_VALUE_INVALID
        if value == 14:
            raise RuntimeError("boom")
        return None

    s = await started(on_write=on_write)
    try:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            await c.write(f"{LD}/GGIO1.Set.setVal[SP]", 42)
            assert await s.read(f"{LD}/GGIO1.Set.setVal[SP]") == 42
            with pytest.raises(iec.ValueInvalid):
                await c.write(f"{LD}/GGIO1.Set.setVal[SP]", 13)
            with pytest.raises(iec.AccessDenied):
                await c.write(f"{LD}/GGIO1.Set.setVal[SP]", 14)
            await c.write(f"{LD}/GGIO1.Arr.vals[SP]", [5, 6, 7, 8])
            assert await c.read(f"{LD}/GGIO1.Set.setVal[SP]") == 42
            # Status values are not writable.
            with pytest.raises(iec.ServiceError):
                await c.write(f"{LD}/GGIO1.Ind1.stVal[ST]", True)
    finally:
        s.stop()
        await s.wait_stopped()
    assert writes[0][1] == f"{LD}/GGIO1.Set.setVal[SP]" and writes[0][2] == 42
    assert isinstance(writes[0][0], int)
    assert writes[-1][2] == [5, 6, 7, 8]


async def test_async_on_write_answering_at_once():
    async def on_write(association, ref, value):
        return iec.DataAccessError.TEMPORARILY_UNAVAILABLE

    async with await started(on_write=on_write) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            with pytest.raises(iec.TemporarilyUnavailable):
                await c.write(f"{LD}/GGIO1.Set.setVal[SP]", 1)


# --- data sets and reports


async def test_data_sets(cli):
    d = await cli.data_set_directory(f"{LD}/LLN0.DS1")
    assert [str(m) for m in d.members][0] == f"{LD}/MMXU1.TotW[MX]" and not d.deletable
    values = await cli.data_set_values(f"{LD}/LLN0.DS1")
    assert values[0][0][0] == 1.5
    await cli.create_data_set("@tmp", [f"{LD}/GGIO1.Ind1.stVal[ST]", f"{LD}/MMXU1.TotW.mag.f[MX]"])
    assert await cli.data_set_values("@tmp") == [False, 1.5]


def updater(server, items, delay=0.05):
    def run():
        for ref, value in items:
            server.update(ref, value)

    t = threading.Timer(delay, run)
    t.start()
    return t


async def test_urcb_driven_from_thread(srv, cli):
    sub = await cli.enable_reporting(f"{LD}/LLN0.urcb01[RP]", gi=True)
    gi = await asyncio.wait_for(sub.__anext__(), 2)
    assert gi.rpt_id == "u1" and len(gi.entries) == 3
    t = updater(srv, [(f"{LD}/GGIO1.Ind2.stVal", True)])
    r = await asyncio.wait_for(sub.__anext__(), 2)
    t.join()
    assert r.inclusion == (False, False, True)
    assert r[f"{LD}/GGIO1.Ind2.stVal[ST]"] is True
    assert r.entries[0].reason == TrgOps.DATA_CHANGE
    await sub.disable()


async def test_brcb_driven_from_thread(srv, cli):
    sub = await cli.enable_reporting(f"{LD}/LLN0.brcb01[BR]", opt_flds=FIELDS | OptFlds.ENTRY_ID)
    t = updater(srv, [(f"{LD}/MMXU1.TotW.mag.f", 9.5), (f"{LD}/GGIO1.Ind1.stVal", True)])
    # Changes of different members may share one report.
    seen = {}
    while len(seen) < 2:
        r = await asyncio.wait_for(sub.__anext__(), 2)
        assert r.rpt_id == "b1" and r.entry_id is not None and not r.entry_id.is_zero
        seen.update(r.values())
    t.join()
    assert seen[f"{LD}/MMXU1.TotW[MX]"][0][0] == 9.5
    assert seen[f"{LD}/GGIO1.Ind1[ST]"][0] is True
    await sub.disable()


# --- control


async def test_direct_normal_sync_hook():
    requests = []
    holder = {}

    def on_control(req):
        requests.append(req)
        if req.ctl_val is False:
            return iec.ControlResult.refused(AddCause.BLOCKED_BY_INTERLOCKING)
        holder["s"].update(f"{req.object}.stVal", req.ctl_val)
        return iec.ControlResult.ok()

    async with await started(on_control=on_control) as s:
        holder["s"] = s
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            ctl = await c.control(f"{LD}/XCBR1.Pos")
            assert ctl.ctl_model is iec.CtlModel.DIRECT_WITH_NORMAL_SECURITY
            await ctl.operate(True, origin=iec.Originator(iec.OrCat.STATION_CONTROL, b"hmi"), interlock_check=True)
            assert await c.read(f"{LD}/XCBR1.Pos.stVal[ST]") is True
            with pytest.raises(iec.ControlRefused) as info:
                await ctl.operate(False)
            assert info.value.add_cause is AddCause.BLOCKED_BY_INTERLOCKING
    req = requests[0]
    assert req.action is ControlAction.OPERATE and str(req.object) == f"{LD}/XCBR1.Pos"
    assert req.ctl_model is iec.CtlModel.DIRECT_WITH_NORMAL_SECURITY
    assert req.ctl_val is True and req.origin == iec.Originator(iec.OrCat.STATION_CONTROL, b"hmi")
    assert req.check == iec.Check.INTERLOCK_CHECK and req.test is False and req.can_complete


async def test_sbo_normal_and_no_hook():
    actions = []

    def on_control(req):
        actions.append(req.action)
        return None  # accepted

    async with await started(on_control=on_control) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            ctl = await c.control(f"{LD}/CSWI1.Pos")
            await ctl.select()
            await ctl.operate(True)
    assert actions == [ControlAction.SELECT, ControlAction.OPERATE]

    async with await started() as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            with pytest.raises(iec.ControlRefused) as info:
                await c.operate(f"{LD}/XCBR1.Pos", True)
            assert info.value.add_cause is AddCause.NOT_SUPPORTED


async def test_enhanced_async_hook():
    async def on_control(req):
        if req.action is not ControlAction.OPERATE:
            return iec.ControlResult.ok()  # answered without suspending
        await asyncio.sleep(0.05)
        if req.ctl_val:
            return iec.ControlResult.ok()
        return iec.ControlResult.refused(AddCause.BLOCKED_BY_PROCESS)

    async with await started(on_control=on_control) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            ctl = await c.control(f"{LD}/CSWI2.Pos")
            assert ctl.ctl_model is iec.CtlModel.DIRECT_WITH_ENHANCED_SECURITY
            await ctl.operate(True, termination_timeout=2)
            with pytest.raises(iec.ControlRefused) as info:
                await ctl.operate(False, termination_timeout=2)
            assert info.value.add_cause is AddCause.BLOCKED_BY_PROCESS

            sbo = await c.control(f"{LD}/CSWI3.Pos")
            await sbo.select_with_value(True)
            await sbo.operate(True, termination_timeout=2)


async def test_pending_completed_from_thread():
    pending = []

    def on_control(req):
        if req.action is ControlAction.OPERATE:
            pending.append(req)
            cause = AddCause.NONE if req.ctl_val else AddCause.INVALID_POSITION
            result = iec.ControlResult.ok() if req.ctl_val else iec.ControlResult.refused(cause)
            threading.Timer(0.05, lambda: req.complete(result)).start()
            return iec.ControlResult.pending()
        return iec.ControlResult.ok()

    async with await started(on_control=on_control) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            ctl = await c.control(f"{LD}/CSWI2.Pos")
            await ctl.operate(True, termination_timeout=2)
            with pytest.raises(iec.ControlRefused) as info:
                await ctl.operate(False, termination_timeout=2)
            assert info.value.add_cause is AddCause.INVALID_POSITION
    assert len(pending) == 2
    await asyncio.sleep(0.1)
    assert pending[0].complete() is False  # already completed


async def test_failing_hooks_refuse():
    def on_control(req):
        raise RuntimeError("boom")

    async def suspends(req):
        await asyncio.sleep(0)
        return iec.ControlResult.ok()

    async with await started(on_control=on_control) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            with pytest.raises(iec.ControlRefused) as info:
                await c.operate(f"{LD}/XCBR1.Pos", True)
            assert info.value.add_cause is AddCause.UNKNOWN

    async with await started(on_control=suspends) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            # Select must be answered at once: a suspending hook refuses it.
            with pytest.raises(iec.ControlRefused):
                await (await c.control(f"{LD}/CSWI1.Pos")).select()
            # An Operate may suspend: it runs on the loop (direct-normal: no termination).
            await c.operate(f"{LD}/XCBR1.Pos", True)


# --- sync facade


def test_sync_server():
    seen = []

    def on_write(association, ref, value):
        seen.append(value)

    with sync.Server.start(MODEL, "127.0.0.1", 0, on_write=on_write) as s:
        with sync.Client.connect("127.0.0.1", s.port, **FAST) as c:
            assert s.association_count == 1
            s.update(f"{LD}/GGIO1.Ind1.stVal", True)
            assert c.read(f"{LD}/GGIO1.Ind1.stVal[ST]") is True
            c.write(f"{LD}/GGIO1.Set.setVal[SP]", 5)
            assert s.read(f"{LD}/GGIO1.Set.setVal[SP]") == 5
    assert seen == [5]


ARRAYS = SCL_DATA / "object_arrays.icd"


async def test_scl_object_arrays_and_foreign_log():
    m = iec.Model.from_scl(ARRAYS)
    sig = m.find("AProt/GGIO1.Sig")
    assert sig.count == 3 and [c.name for c in sig.children] == ["(0)", "(1)", "(2)"]
    assert m.find("AProt/GGIO1.Sig(1).stVal[ST]").reference == "AProt/GGIO1.Sig(1).stVal"
    d = m.type_of("AProt/GGIO1.Sig[SP]")
    assert d.array_size == 3
    assert m.type_of("AProt/GGIO1.Sig(1).setVal[SP]").basic_type == B.INT32
    assert m.find("AProt/LLN0.lcb[LG]") is not None
    assert [lc.log_ld for _, lc in m.log_controls if lc.name == "lcb"] == ["ARec"]
    async with await iec.Server.start(m, "127.0.0.1", 0) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            assert await c.read("AProt/GGIO1.Sig(1).setVal[SP]") == 8
            assert await c.read("AProt/GGIO1.Sig(0).setVal[SP]") == 7
            await c.write("AProt/GGIO1.Sig(0).setVal[SP]", 11)
            assert await c.read("AProt/GGIO1.Sig(0).setVal[SP]") == 11
            assert await srv.read("AProt/GGIO1.Sig(0).setVal[SP]") == 11
            whole = await c.read("AProt/GGIO1.Sig[SP]")
            assert [e["setVal"] if isinstance(e, dict) else e[0] for e in whole] == [11, 8, 7]
            await c.write("AProt/GGIO1.Sig[SP]", [[1], [2], [3]])
            assert await c.read("AProt/GGIO1.Sig(2).setVal[SP]") == 3
            d = await c.data_definition("AProt/GGIO1.Sig")
            assert d.array_size == 3
            assert (await c.data_definition("AProt/GGIO1.Sig(1).stVal[ST]")).basic_type == B.INT32
            assert "stVal" in [e.name for e in await c.data_directory("AProt/GGIO1.Sig")]
            srv.update("AProt/GGIO1.Sig(1).stVal[ST]", 30)
            assert await c.read("AProt/GGIO1.Sig(1).stVal[ST]") == 30
            for _ in range(100):
                if await c.log_status("ARec/LLN0.Events") == 1:
                    break
                await asyncio.sleep(0.01)
            (entry,) = await c.query_log_by_time("ARec/LLN0.Events")
            assert entry.data[0].reference == "AProt/GGIO1$ST$Sig(1)$stVal"
            assert str(entry.data[0].object_reference) == "AProt/GGIO1.Sig(1).stVal[ST]"
            assert entry.data[0].value == 30


def test_builder_object_arrays():
    b = iec.ModelBuilder()
    ld = b.logical_device("LD")
    ln = ld.logical_node("GGIO1")
    arr = ln.data_object("Sig", count=2)
    with pytest.raises(iec.Iec61850Error):
        arr.attribute("v", FC.SP, B.INT32)

    b = iec.ModelBuilder()
    ld = b.logical_device("LD")
    ln = ld.logical_node("GGIO1")
    arr = ln.data_object("Sig", count=2)
    for i in range(2):
        arr.element(i).attribute("v", FC.SP, B.INT32, value=i + 1)
    sub = ln.data_object("Out").sub_object("Sub", count=1)
    sub.element(0).attribute("x", FC.ST, B.BOOLEAN)
    m = b.build()
    assert m.find("LD/GGIO1.Sig(1).v").initial_value == 2
    assert m.find("LD/GGIO1.Out.Sub(0).x") is not None

    b = iec.ModelBuilder()
    arr = b.logical_device("LD").logical_node("GGIO1").data_object("Sig", count=2)
    arr.element(0).attribute("v", FC.SP, B.INT32)
    with pytest.raises(iec.Iec61850Error):
        b.build()  # element 1 is missing


def test_builder_log_of_another_ld():
    b = iec.ModelBuilder()
    a = b.logical_device("A").logical_node("LLN0")
    b.logical_device("B").logical_node("LLN0").log("L")
    a.log_control(iec.LogControl("lcb", log_name="L", log_ln="LLN0", log_ld="B"))
    m = b.build()
    ((_, lc),) = m.log_controls
    assert lc.log_ld == "B"


def test_mms_data_reference():
    r = iec.ObjectReference.from_mms("LD0/GGIO1$ST$Sig(1)$stVal")
    assert str(r) == "LD0/GGIO1.Sig(1).stVal[ST]"


async def test_control_of_array_elements():
    b = iec.ModelBuilder()
    ld = b.logical_device(LD)
    ln = ld.logical_node("CSWI1")
    arr = ln.data_object("Arr", count=2)
    for i in range(2):
        add_controllable(_Prefixed(arr.element(i)), "", iec.CtlModel.DIRECT_WITH_ENHANCED_SECURITY)
    sbo = ln.data_object("Sbo", count=2)
    for i in range(2):
        add_controllable(_Prefixed(sbo.element(i)), "", iec.CtlModel.SBO_WITH_NORMAL_SECURITY)
    pending = {}

    def on_control(req):
        if str(req.object).endswith("Arr(0)") or str(req.object).endswith("Arr(1)"):
            pending[str(req.object)] = req
            return iec.ControlResult.pending()
        return iec.ControlResult.ok()

    async with await iec.Server.start(b.build(), "127.0.0.1", 0, on_control=on_control) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            first = await c.control(f"{LD}/CSWI1.Arr(0)")
            second = await c.control(f"{LD}/CSWI1.Arr(1)")
            assert first.ctl_model is iec.CtlModel.DIRECT_WITH_ENHANCED_SECURITY
            assert first.has_oper_time is False
            op0 = asyncio.ensure_future(first.operate(True))
            op1 = asyncio.ensure_future(second.operate(True))
            for _ in range(200):
                if len(pending) == 2:
                    break
                await asyncio.sleep(0.01)
            assert len(pending) == 2
            pending[f"{LD}/CSWI1.Arr(1)"].complete(iec.ControlResult.refused(AddCause.ABORTION_BY_TRIP))
            with pytest.raises(iec.ControlRefused) as info:
                await op1
            assert info.value.add_cause is AddCause.ABORTION_BY_TRIP
            assert second.last_error.control_object == f"{LD}/CSWI1$CO$Arr(1)$Oper"
            await asyncio.sleep(0.05)
            assert not op0.done() and first.last_error is None
            pending[f"{LD}/CSWI1.Arr(0)"].complete(iec.ControlResult.ok())
            await op0

            await c.operate(f"{LD}/CSWI1.Sbo(1)", True)
            ctl = await c.control(f"{LD}/CSWI1.Sbo(0)")
            await ctl.select()
            await ctl.operate(False)
            with pytest.raises(iec.ObjectNotFound):
                await c.control(f"{LD}/CSWI1.Sbo(2)")


class _Prefixed:
    """Lets add_controllable fill an element of an array of data objects."""

    def __init__(self, element):
        self._element = element

    def data_object(self, _name):
        return self._element
