"""Native features that came late to the binding (ADR 0002): one test per feature of the audit."""

import asyncio
import time

import pytest

import openiec61850 as iec
from openiec61850 import FC, _core, goose as g, sync

from conftest import FAST
from test_server import LD, MODEL, cli, srv  # noqa: F401
from test_services_ext import make_model as make_services_model

GOCB = "IED1LD0/LLN0$GO$gcb01"
DS = "IED1LD0/LLN0$DS1"
READ = 4  # MMS confirmed service read


# --- client options


async def test_iso_parameters_reach_the_stack(srv):  # noqa: F811
    iso = iec.IsoParameters(
        session_versions=3,
        local_reference=7,
        read_buffer_size=1024,
        max_output_bytes=1 << 20,
        write_stall_timeout=5.0,
        max_tsdu_size=1 << 16,
        max_tpkt_size=4096,
        version_number=1,
        connect_timeout=1.0,
        handshake_timeout=1.0,
        association_timeout=1.0,
    )
    async with await iec.Client.connect("127.0.0.1", srv.port, iso=iso, **FAST) as c:
        assert await c.server_directory() == [LD]


async def test_initiate_proposal_is_sent(srv):  # noqa: F811
    seen = []

    def authorize(request):
        seen.append(request)
        return True

    s = await iec.Server.start(MODEL, "127.0.0.1", 0, authorize=authorize)
    default = iec.Client.connect("127.0.0.1", s.port, **FAST)
    async with await default as c:
        cbb = c.association_info.negotiated.parameter_cbb
    iso = iec.IsoParameters(max_serv_outstanding_calling=3, nesting_level=4, parameter_cbb=cbb)
    async with await iec.Client.connect("127.0.0.1", s.port, iso=iso, **FAST) as c:
        assert c.association_info.negotiated.parameter_cbb == cbb
    s.stop()
    await s.wait_stopped()
    assert seen[1].max_serv_outstanding_calling == 3 and seen[1].nesting_level == 4
    assert seen[1].called_presentation_selector == b"\x00\x00\x00\x01"
    assert seen[1].local_detail_calling == 65000 and seen[1].mechanism_name is None


async def test_invalid_support_options_are_refused(srv):  # noqa: F811
    with pytest.raises(ValueError):
        await iec.Client.connect("127.0.0.1", srv.port, iso=iec.IsoParameters(parameter_cbb=(b"\xff", 9)), **FAST)


# --- client services


async def test_service_specific_info(client, server):
    server.fail_next(READ, error_class=int(iec.ErrorClass.ACCESS), error_code=3,
                     service_specific_info=b"\x01\x02")
    with pytest.raises(iec.ServiceError) as info:
        await client.read("IED1LD1/GGIO1.Ind1.stVal[ST]")
    assert info.value.service_specific_info == b"\x01\x02"


async def test_control_structure(cli):  # noqa: F811
    ctl = await cli.control(f"{LD}/CSWI3.Pos")
    assert ctl.ctl_val_type is iec.MmsType.BOOLEAN
    assert ctl.structure.kind is iec.DefinitionKind.STRUCTURE
    assert ctl.structure["Oper"]["ctlVal"].mms_type is iec.MmsType.BOOLEAN
    assert ctl.structure["Oper"].find("Check") is not None
    bare = await cli.control(f"{LD}/CSWI3.Pos", read_structure=False)
    assert bare.ctl_val_type is None and bare.structure is None


def test_sync_facade_follows(srv_model_port):
    with sync.Client.connect("127.0.0.1", srv_model_port, **FAST) as c:
        assert c.edition is iec.Edition.ED2
        ctl = c.control(f"{LD}/CSWI3.Pos")
        assert ctl.ctl_val_type is iec.MmsType.BOOLEAN
        assert ctl.structure["Oper"]["ctlVal"].mms_type is iec.MmsType.BOOLEAN


@pytest.fixture
def srv_model_port():
    with sync.Server.start(MODEL, "127.0.0.1", 0) as s:
        yield s.port


def test_sync_log_entries():
    with sync.Server.start(make_services_model(), "127.0.0.1", 0) as s:
        s.update(f"{LD}/GGIO1.Ind1.stVal[ST]", True)
        with sync.Client.connect("127.0.0.1", s.port, **FAST) as c:
            c.set_lcb_values(f"{LD}/LLN0.lcb01[LG]", log_ena=True)
            s.update(f"{LD}/GGIO1.Ind1.stVal[ST]", False)
            deadline = time.monotonic() + 2
            while c.log_status(f"{LD}/LLN0.EventLog") == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            entries = list(c.log_entries(f"{LD}/LLN0.EventLog"))
    assert entries and entries[0].values()


# --- server options


async def test_responding_ap_title():
    async with await iec.Server.start(MODEL, "127.0.0.1", 0, ap_title="1.3.9999.7", ae_qualifier=33) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            assert c.association_info.peer_ap_title == "1.3.9999.7"
            assert c.association_info.peer_ae_qualifier == 33
    async with await iec.Server.start(MODEL, "127.0.0.1", 0, ap_title=None, ae_qualifier=None) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            assert c.association_info.peer_ap_title is None
            assert c.association_info.peer_ae_qualifier is None


async def test_server_iso_limits():
    iso = iec.ServerIsoParameters(
        local_detail=20000,
        max_serv_outstanding_calling=2,
        max_serv_outstanding_called=2,
        nesting_level=5,
        max_nesting=8,
        read_buffer_size=1024,
        max_output_bytes=1 << 20,
        write_stall_timeout=5.0,
        max_tpdu_size=1024,
        no_delay=True,
        keep_alive=True,
    )
    async with await iec.Server.start(MODEL, "127.0.0.1", 0, iso=iso) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, **FAST) as c:
            n = c.association_info.negotiated
            assert (n.local_detail_called, n.max_serv_outstanding_calling) == (20000, 2)
            assert n.data_structure_nesting_level == 5
            assert await c.server_directory() == [LD]


async def test_server_selectors():
    iso = iec.ServerIsoParameters(session_selector=b"\x00\x02", presentation_selector=b"\x00\x00\x00\x02")
    async with await iec.Server.start(MODEL, "127.0.0.1", 0, iso=iso) as s:
        client_iso = iec.IsoParameters(called_session_selector=b"\x00\x02",
                                       called_presentation_selector=b"\x00\x00\x00\x02")
        async with await iec.Client.connect("127.0.0.1", s.port, iso=client_iso, **FAST) as c:
            assert await c.server_directory() == [LD]


async def test_accept_connection_filters_tsaps():
    seen = []

    def accept(calling, called):
        seen.append((calling, called))
        return None if called == b"\x00\x01" else 2

    async with await iec.Server.start(MODEL, "127.0.0.1", 0, accept_connection=accept) as s:
        good = iec.IsoParameters(calling_tsap=b"\x00\x05", called_tsap=b"\x00\x01")
        async with await iec.Client.connect("127.0.0.1", s.port, iso=good, **FAST):
            pass
        with pytest.raises(iec.ConnectionRefused):
            await iec.Client.connect("127.0.0.1", s.port, iso=iec.IsoParameters(called_tsap=b"\x00\x09"), **FAST)
    assert seen[0] == (b"\x00\x05", b"\x00\x01")


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_accept_connection_exception_refuses():
    def accept(calling, called):
        raise RuntimeError("no")

    async with await iec.Server.start(MODEL, "127.0.0.1", 0, accept_connection=accept) as s:
        with pytest.raises(iec.ConnectionRefused):
            await iec.Client.connect("127.0.0.1", s.port, **FAST)


@pytest.mark.parametrize(
    ("answer", "error"),
    [
        (False, iec.AuthenticationFailed),
        (iec.AcseDiagnostic.AUTHENTICATION_FAILURE, iec.AuthenticationFailed),
        (iec.AcseDiagnostic.CALLING_AP_TITLE_NOT_RECOGNIZED, iec.AssociationRejected),
    ],
)
async def test_authorize_diagnostic(answer, error):
    async with await iec.Server.start(MODEL, "127.0.0.1", 0, authorize=lambda r: answer) as s:
        with pytest.raises(error) as info:
            await iec.Client.connect("127.0.0.1", s.port, **FAST)
        if answer is iec.AcseDiagnostic.CALLING_AP_TITLE_NOT_RECOGNIZED:
            assert not isinstance(info.value, iec.AuthenticationFailed)


# --- server model and files


def test_model_node_navigation():
    node = MODEL.find(f"{LD}/MMXU1.TotW.mag.f[MX]")
    assert node.logical_node.name == "MMXU1"
    assert node.logical_device.name == LD
    assert MODEL.logical_devices[0].logical_node is None
    assert MODEL.find(f"{LD}/MMXU1").has_fc(FC.MX) and MODEL.find(f"{LD}/MMXU1").has_fc("CF")
    assert not MODEL.find(f"{LD}/MMXU1").has_fc(FC.CO)
    with pytest.raises(ValueError):
        MODEL.find(LD).has_fc("nope")


def test_model_group_values():
    model = make_services_model()
    node = model.find(f"{LD}/PTOC1.StrVal.setMag.f[SG]")
    assert node.group_values == (1.0, 2.0, 3.0)
    assert model.find(f"{LD}/GGIO1.Ind1.stVal[ST]").group_values == ()
    assert node.has_fc(FC.SE)


def test_normalize_file_path():
    assert iec.normalize_file_path("/COMTRADE/a.cfg") == "COMTRADE/a.cfg"
    assert iec.normalize_file_path("/") == ""
    with pytest.raises(iec.FileStoreError):
        iec.normalize_file_path("a/../b")


# --- GOOSE and SV without I/O


def test_goose_frame_round_trip():
    when = iec.Timestamp.from_raw(1_700_000_000, 0, 0)
    frame = g.encode_goose(
        "01-0C-CD-01-00-01",
        "02-00-00-00-00-01",
        gocb_ref=GOCB,
        dat_set=DS,
        values=[True, iec.Int32(7)],
        go_id="GO1",
        time_allowed_to_live=2000,
        t=when,
        st_num=5,
        sq_num=2,
        simulation=True,
        conf_rev=9,
        nds_com=True,
        vlan=g.VlanTag(priority=6, id=10),
        app_id=0x1000,
        reserved1=0x8000,
    )
    assert g.peek_ether_type(frame) == g.ETHERTYPE_GOOSE
    h = g.decode_frame(frame)
    assert h.ether_type == g.ETHERTYPE_GOOSE and h.app_id == 0x1000 and h.simulation
    assert h.vlan == g.VlanTag(priority=6, id=10) and h.destination == "01-0C-CD-01-00-01"
    assert len(h.apdu) == h.length - 8
    m = g.decode_goose(frame)
    assert (m.gocb_ref, m.dat_set, m.go_id, m.st_num, m.sq_num) == (GOCB, DS, "GO1", 5, 2)
    assert m.values == (True, 7) and m.t == when and m.nds_com and m.simulation
    assert m.num_dat_set_entries == 2 and m.security is None
    assert m.sequence is g.SequenceStatus.FIRST


def test_frame_errors():
    with pytest.raises(iec.Iec61850Error):
        g.decode_goose(b"\x00" * 10)
    assert g.peek_ether_type(b"\x00" * 4) == 0
    assert g.is_multicast("01-0C-CD-01-00-01") and not g.is_multicast(b"\x02\x00\x00\x00\x00\x01")


def test_sv_frame_round_trip():
    seq = g.LeSamples.from_measurements(currents=(1.0, 2.0, 3.0, 0.0), voltages=(1.0, 2.0, 3.0, 0.0))
    refr = iec.Timestamp.from_raw(1_700_000_000, 0, 0)
    asdus = [
        g.SvAsdu("MU01", seq, dat_set="LD/LLN0$PhsMeas1", smp_cnt=11, conf_rev=2, refr_tm=refr, smp_synch=g.SmpSynch.GLOBAL,
                 smp_rate=4000, smp_mod=1, gm_identity=b"12345678"),
        g.SvAsdu("MU01", b"\x00" * 8, smp_cnt=12),
    ]
    frame = g.encode_sv("01-0C-CD-04-00-01", "02-00-00-00-00-01", asdus, app_id=0x4001)
    assert g.peek_ether_type(frame) == g.ETHERTYPE_SV
    decoded = g.decode_sv(frame)
    assert decoded.header.app_id == 0x4001 and decoded.security is None
    first, second = decoded.asdus
    assert first.sv_id == "MU01" and first.dat_set == "LD/LLN0$PhsMeas1" and first.smp_cnt == 11
    assert first.refr_tm == refr and first.smp_rate == 4000 and first.smp_mod == 1
    assert first.gm_identity == b"12345678" and first.seq_data == seq.encode()
    assert second.smp_cnt == 12 and second.dat_set is None
    with pytest.raises(iec.Iec61850Error):
        g.encode_sv("01-0C-CD-04-00-01", "02-00-00-00-00-01", [])


def test_retransmission_curve():
    curve = [g.retransmission_interval(n, 4, 1000) for n in (1, 2, 3, 8, 9, 40)]
    assert curve == [4, 8, 16, 512, 1000, 1000]


def test_le_constants():
    assert g.samples_per_second(g.SAMPLES_PER_PERIOD_PROTECTION, 50) == 4000
    assert g.samples_per_second(g.SAMPLES_PER_PERIOD_METERING, 60) == 15360


def test_sequence_tracker():
    t = g.SequenceTracker(margin=50)
    assert not t.has_state and t.deadline is None and not t.expired(0.0)
    assert t.on_message(1, 0, 100, now=10.0).status is g.SequenceStatus.FIRST
    assert t.on_message(1, 1, 100, now=10.05).status is g.SequenceStatus.RETRANSMISSION
    assert (t.st_num, t.sq_num) == (1, 1) and t.has_state
    gap = t.on_message(1, 4, 100, now=10.1)
    assert gap.status is g.SequenceStatus.SQ_GAP and gap.lost == 2
    assert t.deadline == pytest.approx(10.25)
    assert not t.expired(10.2) and t.expired(10.3)
    assert t.on_message(1, 4, 100, now=10.2).status is g.SequenceStatus.DUPLICATE
    assert t.on_message(1, 3, 100, now=10.2).status is g.SequenceStatus.OUT_OF_ORDER
    t.reset()
    assert t.on_message(2, 0, 100).status is g.SequenceStatus.FIRST


def test_smp_cnt_tracker():
    t = g.SmpCntTracker(wrap=4000)
    assert t.on_sample(3998)[0] is g.Continuity.FIRST
    assert t.on_sample(3999)[0] is g.Continuity.IN_SEQUENCE
    assert t.on_sample(0)[0] is g.Continuity.IN_SEQUENCE
    assert t.on_sample(3) == (g.Continuity.GAP, 2)
    assert t.on_sample(3)[0] is g.Continuity.DUPLICATE
    t.reset()
    assert t.on_sample(9)[0] is g.Continuity.FIRST


async def test_loopback_filter_injects_loss():
    net = g.LoopbackNetwork()
    tx = net.attach("02-00-00-00-00-01")
    a = net.attach("02-00-00-00-00-02")
    b = net.attach("02-00-00-00-00-03")
    seen = []

    def keep(frame, to):
        seen.append((g.peek_ether_type(frame), to))
        return to != "02-00-00-00-00-03"

    net.set_filter(keep)
    cfg = g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS, min_time=2, max_time=20)
    async with g.Receiver(a) as ra, g.Receiver(b) as rb:
        kept = ra.subscribe(gocb_ref=GOCB)
        lost = rb.subscribe(gocb_ref=GOCB)
        with g.GoosePublisher(tx, cfg, [True]) as pub:
            pub.start()
            first = await kept.get(timeout=2)
            assert first.kind is g.GooseEventKind.MESSAGE
            with pytest.raises(asyncio.TimeoutError):
                await lost.get(timeout=0.1)
            pub.stop()
        net.set_filter(None)
        count = len(seen)
        tx.send(g.encode_goose("01-0C-CD-01-00-00", tx.address, gocb_ref=GOCB, dat_set=DS, values=[True]))
        assert (await lost.get(timeout=2)).kind is g.GooseEventKind.MESSAGE
        assert len(seen) == count
    assert (g.ETHERTYPE_GOOSE, "02-00-00-00-00-03") in seen


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_loopback_filter_exception_keeps_the_frame():
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")

    def broken(frame, to):
        raise RuntimeError("no")

    net.set_filter(broken)
    async with g.Receiver(rx) as r:
        sub = r.subscribe(gocb_ref=GOCB)
        tx.send(g.encode_goose("01-0C-CD-01-00-00", tx.address, gocb_ref=GOCB, dat_set=DS, values=[True]))
        assert (await sub.get(timeout=2)).message.values == (True,)
    net.set_filter(None)


def test_interface_index_is_for_raw_sockets():
    assert g.LoopbackNetwork().attach()._native.interface_index is None


def test_core_stub_lists_the_new_names():
    for name in ("normalize_file_path", "goose_decode", "goose_encode", "sv_decode", "sv_encode",
                 "goose_decode_frame", "goose_peek_ether_type", "goose_retransmission_interval",
                 "SequenceTracker", "SmpCntTracker"):
        assert hasattr(_core, name)
