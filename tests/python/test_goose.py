"""GOOSE and Sampled Values publishers / subscribers over the loopback network."""

import asyncio
import errno
import gc

import pytest

import openiec61850 as iec
from openiec61850 import goose as g

GOCB = "IED1LD0/LLN0$GO$gcb01"
DS = "IED1LD0/LLN0$DS1"

SCD = """<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="goose-test"/>
  <Communication>
    <SubNetwork name="ProcessBus" type="8-MMS">
      <ConnectedAP iedName="IED1" apName="P1">
        <GSE ldInst="LD0" cbName="gcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-10</P>
            <P type="APPID">0010</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">6</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">2000</MaxTime>
        </GSE>
        <SMV ldInst="MU" cbName="msv1">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4001</P>
          </Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1">
    <AccessPoint name="P1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="q" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" datSet="ds1" appID="IED1_GOOSE" confRev="3"/>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
        <LDevice inst="MU">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="PhsMeas1">
              <FCDA ldInst="MU" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <SampledValueControl name="msv1" datSet="PhsMeas1" smvID="IED1MU01" confRev="2"
                                 smpRate="80" nofASDU="1" smpMod="SmpPerPeriod">
              <SmvOpts refreshTime="true" sampleRate="true" dataSet="true"/>
            </SampledValueControl>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Beh" type="ENS_T"/></LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Beh" type="ENS_T"/>
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENS_T" cdc="ENS">
      <DA name="stVal" bType="Enum" type="BehKind" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <EnumType id="BehKind"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"""


async def next_message(sub, timeout=5.0):
    while True:
        e = await sub.get(timeout)
        if e.kind is g.GooseEventKind.MESSAGE:
            return e.message


async def test_goose_pub_sub():
    net = g.LoopbackNetwork()
    tx = net.attach("00-11-22-33-44-55")
    rx = net.attach("00-11-22-33-44-66")
    assert tx.address == "00-11-22-33-44-55"
    cfg = g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS, go_id="GO1", app_id=0x1000, min_time=4, max_time=200)
    async with g.Receiver(rx) as receiver:
        sub = receiver.subscribe(gocb_ref=GOCB, app_id=0x1000, dat_set=DS, go_id="GO1", num_entries=2)
        with g.GoosePublisher(tx, cfg, [False, iec.Int32(7)]) as pub:
            pub.start()
            m = await next_message(sub)
            assert (m.gocb_ref, m.dat_set, m.go_id, m.app_id) == (GOCB, DS, "GO1", 0x1000)
            assert m.st_num == 1 and m.sq_num == 0 and m.sequence is g.SequenceStatus.FIRST
            assert m.values == (False, 7)
            assert m.source == "00-11-22-33-44-55" and m.destination == "01-0C-CD-01-00-00"
            assert m.vlan == g.VlanTag() and isinstance(m.t, iec.Timestamp)
            assert m.time_allowed_to_live > 0

            pub.publish([True, 8])  # plain int typed like the previous value
            while True:
                m = await next_message(sub)
                if m.st_num == 2:
                    break
            assert m.values == (True, 8) and m.sq_num == 0
            assert m.sequence is g.SequenceStatus.NEW_STATE
            assert pub.update([True, 8]) is False
            assert pub.update([True, 9]) is True
            while (await next_message(sub)).st_num != 3:
                pass
            s = pub.stats
            assert s.st_num == 3 and s.messages_sent >= 3 and s.send_errors == 0

            # Retransmissions arrive with growing sqNum.
            m = await next_message(sub)
            assert m.st_num == 3 and m.sequence in (g.SequenceStatus.RETRANSMISSION, g.SequenceStatus.SQ_GAP)

            batch = await sub.get_batch(timeout=5.0)
            assert batch and all(isinstance(e, g.GooseEvent) for e in batch)
        # Stopped: the subscriber sees a TAL timeout.
        while True:
            e = await sub.get(5.0)
            if e.kind is g.GooseEventKind.TIMEOUT:
                break
        assert e.message.gocb_ref == GOCB
        st = sub.stats
        assert st.messages >= 4 and st.timeouts == 1
        assert receiver.stats.frames >= 4
    # Stopping the receiver ends the subscription.
    with pytest.raises(StopAsyncIteration):
        while True:
            await sub.get(5.0)
    assert sub.closed


async def test_goose_mismatch_and_filters():
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")
    cfg = g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS, conf_rev=5, app_id=1)
    with g.Receiver(rx) as receiver:
        bad = receiver.subscribe(g.GooseSubscriberConfig(gocb_ref=GOCB, conf_rev=4))
        other = receiver.subscribe(gocb_ref="IED2LD0/LLN0$GO$x")
        pub = g.GoosePublisher(tx, cfg, [iec.Float32(1.5)])
        pub.start()
        e = await bad.get(5.0)
        assert e.kind is g.GooseEventKind.MISMATCH and e.reason is g.MismatchReason.CONF_REV
        assert e.message.conf_rev == 5
        with pytest.raises(TimeoutError):
            await other.get(0.2)
        pub.stop()
        other.close()
        with pytest.raises(StopAsyncIteration):
            await other.get(5.0)


async def test_goose_subscription_survives_timeouts_without_loss():
    # Waiting with a timeout never loses events: they stay queued in Python.
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")
    with g.Receiver(rx) as receiver:
        sub = receiver.subscribe(gocb_ref=GOCB)
        with pytest.raises(TimeoutError):
            await sub.get(0.05)
        pub = g.GoosePublisher(tx, g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS), [True])
        pub.publish([False])
        m = await next_message(sub)
        assert m.values == (False,)
        pub.stop()


def test_goose_config_from_scl(tmp_path):
    pc = g.GoosePublisherConfig.from_scl(SCD, "IED1", "LD0", "gcb1")
    assert pc.destination == "01-0C-CD-01-00-10" and pc.app_id == 0x10
    assert pc.vlan == g.VlanTag(priority=6, id=10)
    assert (pc.gocb_ref, pc.dat_set, pc.go_id, pc.conf_rev) == ("IED1LD0/LLN0$GO$gcb1", "IED1LD0/LLN0$ds1", "IED1_GOOSE", 3)
    assert (pc.min_time, pc.max_time) == (4, 2000)
    path = tmp_path / "test.scd"
    path.write_text(SCD)
    sc = g.GooseSubscriberConfig.from_scl(path, "IED1", "LD0", "gcb1", "P1")
    assert sc.app_id == 0x10 and sc.num_entries == 2 and sc.go_id == "IED1_GOOSE"
    assert sc.destination == "01-0C-CD-01-00-10"
    with pytest.raises(iec.InvalidOperation):
        g.GoosePublisherConfig.from_scl(SCD, "IED2", "LD0", "gcb1")

    sp = g.SvPublisherConfig.from_scl(SCD, "IED1", "MU", "msv1")
    assert sp.sv_id == "IED1MU01" and sp.app_id == 0x4001 and sp.smp_rate == 80
    assert sp.refresh_time and sp.smp_cnt_wrap == 4000 and sp.dat_set == "IED1MU/LLN0$PhsMeas1"
    ss = g.SvSubscriberConfig.from_scl(SCD.encode(), "IED1", "MU", "msv1", frequency=60)
    assert ss.smp_cnt_wrap == 4800 and ss.conf_rev == 2 and ss.destination == "01-0C-CD-04-00-01"


def test_le_samples():
    s = g.LeSamples.from_measurements([1.0, -2.5, 0.001, 0], [230.0, 0, 0, 0.01], qualities=[0, 1, 0, 0, 0, 0, 0, 1 << 13])
    assert s.values[:2] == (1000, -2500) and s.values[4] == 23000 and s.values[7] == 1
    assert s.currents[1] == pytest.approx(-2.5) and s.voltages[0] == pytest.approx(230.0)
    assert s.validity(1) is iec.Validity.INVALID and s.derived(7)
    data = s.encode()
    assert len(data) == 64
    assert g.LeSamples.decode(data) == s
    # Same wire format as the native 9-2 LE helpers.
    assert iec._core.le_encode(list(zip(s.values, s.qualities))) == data
    assert [tuple(c) for c in iec._core.le_decode(data)] == list(zip(s.values, s.qualities))
    big = g.LeSamples.from_measurements([1e12, 0, 0, 0])
    assert big.values[0] == 2**31 - 1
    with pytest.raises(ValueError):
        g.LeSamples.decode(b"\0" * 10)


async def test_sv_pub_sub_batches():
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")
    cfg = g.SvPublisherConfig(sv_id="MU01", dat_set="MU/LLN0$PhsMeas1", smp_cnt_wrap=4000, asdus_per_frame=2,
                              smp_rate=80, refresh_time=True, conf_rev=3)
    with g.Receiver(rx) as receiver:
        sub = receiver.subscribe_sv(sv_id="MU01", smp_cnt_wrap=4000, conf_rev=2, queue_capacity=10000)
        pub = g.SvPublisher(tx, cfg)
        n = 4000 + 10
        for i in range(n):
            assert pub.push(g.LeSamples.from_measurements([i * 0.001, 0, 0, 0])) == i % 4000
        assert pub.stats.frames_sent == n // 2
        got = []
        batches = 0
        async for b in sub.batches():
            batches += 1
            got.extend(b)
            if len(got) >= n:
                break
        assert len(got) == n and batches < n  # delivered in batches
        assert [s.smp_cnt for s in got[:3]] == [0, 1, 2] and got[4000].smp_cnt == 0
        first = got[0]
        assert first.status is g.Continuity.FIRST
        assert all(s.status is g.Continuity.IN_SEQUENCE for s in got[1:])
        assert first.conf_rev == 3 and first.conf_rev_mismatch
        assert first.sv_id == "MU01" and first.dat_set == "MU/LLN0$PhsMeas1" and first.smp_rate == 80
        assert isinstance(first.refr_tm, iec.Timestamp)
        assert got[5].le.values[0] == 5
        assert sub.dropped == 0 and sub.stats.samples == n


async def test_sv_iteration_and_timer_source():
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")
    with g.Receiver(rx) as receiver:
        sub = receiver.subscribe_sv(g.SvSubscriberConfig(sv_id="MU02"))
        pub = g.SvPublisher(tx, g.SvPublisherConfig(sv_id="MU02", smp_cnt_wrap=0))
        pub.start(0.001, lambda cnt: g.LeSamples(values=(cnt,) + (0,) * 7))
        seen = []
        async for s in sub:
            seen.append(s)
            if len(seen) == 20:
                break
        pub.stop()
        assert [s.le.values[0] for s in seen] == [s.smp_cnt for s in seen]
        assert seen[0].source == "02-00-00-00-00-01"
        with pytest.raises(ValueError):
            pub.start(0, lambda cnt: b"")


async def test_sv_queue_overflow_counts_drops():
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02", queue_capacity=4096)
    with g.Receiver(rx) as receiver:
        sub = receiver.subscribe_sv(sv_id="MU03", queue_capacity=8, max_batch=8)
        pub = g.SvPublisher(tx, g.SvPublisherConfig(sv_id="MU03"))
        # The first sample is delivered at once; the following ones pile up natively.
        pub.push(b"\0" * 64)
        await sub.get(5.0)
        for _ in range(100):
            pub.push(b"\0" * 64)
        deadline = asyncio.get_running_loop().time() + 5
        while sub.stats.samples < 101 and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        b = await sub.get_batch(timeout=5.0)
        assert len(b) <= 8
        assert sub.dropped > 0


async def test_subscription_garbage_collected():
    net = g.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")
    with g.Receiver(rx) as receiver:
        sub = receiver.subscribe(gocb_ref=GOCB)
        del sub
        gc.collect()
        pub = g.GoosePublisher(tx, g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS), [True])
        pub.start()
        await asyncio.sleep(0.05)
        pub.stop()


def test_publisher_errors():
    net = g.LoopbackNetwork()
    tx = net.attach()
    with pytest.raises(iec.InvalidOperation):
        g.GoosePublisher(tx, g.GoosePublisherConfig(gocb_ref="", dat_set=DS), [True])
    with pytest.raises(iec.InvalidOperation):
        g.GoosePublisher(tx, g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS, min_time=0), [True])
    with pytest.raises(iec.InvalidOperation):
        g.SvPublisher(tx, g.SvPublisherConfig(sv_id=""))
    with pytest.raises(ValueError):
        net.attach("00-11")
    with pytest.raises(TypeError):
        g.GoosePublisher(tx, g.GoosePublisherConfig(gocb_ref=GOCB, dat_set=DS), [3])  # untyped
    tx.close()


def test_raw_socket_link():
    try:
        link = g.RawSocketLink.open("lo")
    except iec.Iec61850Error as e:
        if getattr(e, "errno", None) in (errno.EPERM, errno.EACCES) or isinstance(e, iec.NotSupported):
            pytest.skip("raw sockets need CAP_NET_RAW on Linux")
        raise
    with link:
        assert len(link.address) == 17
    with pytest.raises(iec.Iec61850Error):
        g.RawSocketLink.open("no-such-if0")
