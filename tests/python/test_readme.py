"""Runs the Python examples of the README as written, against a local server.

Only the outside world is replaced: the host, port 102 and privileged raw sockets go to loopback,
the file names to models built here, and the loops that would run forever end after one item.
"""

import ast
import asyncio
import inspect
import re
from pathlib import Path

import pytest

import openiec61850 as iec
from openiec61850 import FC, BasicType as B, TrgOps, goose

from test_server import add_controllable

README = Path(__file__).parents[2] / "README.md"
BLOCKS = re.findall(r"```python\n(.*?)```", README.read_text(), re.S)


def model():
    """The objects the examples name."""
    b = iec.ModelBuilder()
    ld0 = b.logical_device("IED1LD0")
    lln0 = ld0.logical_node("LLN0")
    lln0.data_object("Mod").attribute("stVal", FC.ST, B.ENUMERATED, value=1)
    mmxu = ld0.logical_node("MMXU1")
    totw = mmxu.data_object("TotW")
    totw.structure("mag", FC.MX).attribute("f", B.FLOAT32, triggers=TrgOps.DATA_CHANGE, value=1.5)
    totw.attribute("db", FC.CF, B.INT32U, value=7)
    ptoc = ld0.logical_node("PTOC1")
    set_mag = ptoc.data_object("StrVal").structure("setMag", FC.SG).attribute("f", B.FLOAT32)
    set_mag.group_value(1, 1.0).group_value(2, 2.0).group_value(3, 3.0)
    lln0.setting_group_control(num_of_sgs=3, act_sg=1)
    lln0.data_set("DS1", ["IED1LD0/MMXU1.TotW.mag.f[MX]"])
    lln0.log("EventLog")
    lln0.log_control(iec.LogControl("lcb01", data_set="DS1", log_name="EventLog", log_ena=True, trg_ops=TrgOps.DATA_CHANGE))
    lln0.goose_control(iec.GooseControl("gcb01", go_id="G1", data_set="DS1"))
    lln0.report_control(iec.ReportControl("urcb01", rpt_id="u1", data_set="DS1", trg_ops=TrgOps.DATA_CHANGE | TrgOps.GENERAL_INTERROGATION))
    ld1 = b.logical_device("IED1LD1")
    ld1.logical_node("LLN0").data_object("Mod").attribute("stVal", FC.ST, B.ENUMERATED, value=1)
    add_controllable(ld1.logical_node("XCBR1"), "Pos", iec.CtlModel.SBO_WITH_ENHANCED_SECURITY)
    add_controllable(ld1.logical_node("GGIO1"), "SPCSO1", iec.CtlModel.DIRECT_WITH_NORMAL_SECURITY)
    b2 = b.logical_device("Bay1Prot").logical_node("MMXU1").data_object("Hz")
    b2.structure("mag", FC.MX).attribute("f", B.FLOAT32)
    b2.attribute("q", FC.MX, B.QUALITY)
    b2.attribute("t", FC.MX, B.TIMESTAMP)
    return b.build()


def run_block(index, namespace):
    """The block, with top-level await allowed; a coroutine when it awaits. asyncio.run() of the
    two complete programs is left to the test, which already runs on a loop."""
    source = BLOCKS[index].replace("asyncio.run(main())", "")
    code = compile(source, f"README block {index}", "exec", ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
    result = eval(code, namespace)  # noqa: S307 - our own README
    return result if inspect.isawaitable(result) else None


@pytest.fixture
def local(monkeypatch, tmp_path):
    """Sends Client.connect to a server of the README's model and Server.start to free ports."""
    monkeypatch.chdir(tmp_path)
    state = type("State", (), {"port": None, "subscriptions": [], "tls": [], "servers": []})()
    connect = iec.Client.connect.__func__
    enable = iec.Client.enable_reporting
    start = iec.Server.start.__func__

    async def fake_connect(cls, host, port=102, **options):
        if options.pop("tls", None) is not None:
            state.tls.append(port)
        return await connect(cls, "127.0.0.1", state.port, **options)

    async def fake_enable(self, *args, **kwargs):
        sub = await enable(self, *args, **kwargs)
        state.subscriptions.append(sub)
        return sub

    async def fake_start(cls, m, host="0.0.0.0", port=102, **options):
        s = await start(cls, m, "127.0.0.1", 0, **options)
        state.servers.append(s)
        return s

    monkeypatch.setattr(iec.Client, "connect", classmethod(fake_connect))
    monkeypatch.setattr(iec.Client, "enable_reporting", fake_enable)
    monkeypatch.setattr(iec.Server, "start", classmethod(fake_start))
    monkeypatch.setattr(iec.Model, "from_scl", classmethod(lambda cls, *a, **k: model()))
    return state


def test_every_block_is_covered():
    assert len(BLOCKS) == 5


async def serve(state, **options):
    async def on_control(request):
        return iec.ControlResult.ok()

    s = await iec.Server.start(model(), on_control=on_control, **options)
    state.port = s.port
    return s


async def stop(state):
    for s in state.servers:
        s.stop()
        await s.wait_stopped()


async def test_client_example(local):
    await serve(local)
    printed = []

    def fake_print(*args):
        printed.append(args)
        if len(args) == 4:  # the report loop: one report is enough
            local.subscriptions[-1]._end()

    namespace = {"__name__": "readme", "print": fake_print}
    run_block(0, namespace)
    await asyncio.wait_for(namespace["main"](), 10)
    await stop(local)
    assert printed[0] == (["Bay1Prot", "IED1LD0", "IED1LD1"],)
    assert printed[1] == (1.5,)
    assert len(printed[2]) == 4 and str(printed[2][1]) == "IED1LD0/MMXU1.TotW.mag.f[MX]"


async def test_server_example(local):
    namespace = {"__name__": "readme"}
    run_block(1, namespace)
    asyncio.get_running_loop().call_later(0.2, lambda: [s.stop() for s in local.servers])
    await asyncio.wait_for(namespace["main"](), 5)
    assert len(local.servers) == 1
    # The hook the example defines, as the server would call it.
    assert await namespace["on_control"](None) == iec.ControlResult.ok()


async def test_services_example(local, monkeypatch):
    comtrade = Path("files/COMTRADE")
    comtrade.mkdir(parents=True)
    (comtrade / "a.cfg").write_bytes(b"cfg")
    root = comtrade.parent.resolve()
    real = iec.DirectoryFileStore
    monkeypatch.setattr(iec, "DirectoryFileStore", lambda path: real(root))
    Path("new.cfg").write_bytes(b"new")
    await serve(local, files=real(root), on_obtain_file=lambda event: True)
    namespace = {"iec": iec, "model": model(), "print": lambda *a: None}
    await run_block(2, namespace)
    assert Path("COMTRADE_a.cfg").read_bytes() == b"cfg"
    assert (root / "settings/new.cfg").read_bytes() == b"new"
    await stop(local)


async def test_tls_example(local):
    await serve(local)
    namespace = {"iec": iec}
    await run_block(3, namespace)
    assert namespace["tls"].ca_file == "ca.pem" and local.tls == [iec.TLS_PORT]
    namespace["client"].abort()
    await stop(local)


async def test_goose_example(monkeypatch):
    net = goose.LoopbackNetwork()
    tx, rx = net.attach("02-00-00-00-00-01"), net.attach("02-00-00-00-00-02")
    sv_tx = net.attach("02-00-00-00-00-03")
    config = goose.GoosePublisherConfig(gocb_ref="BAY1LD0/LLN0$GO$gcb01", dat_set="BAY1LD0/LLN0$DS1",
                                        min_time=4, max_time=50)
    monkeypatch.setattr(goose.RawSocketLink, "open", classmethod(lambda cls, name: tx))
    monkeypatch.setattr(goose.GoosePublisherConfig, "from_scl", classmethod(lambda cls, *a: config))

    # The example has one link, on which a real interface would hide our own frames: here the
    # receiver reads another one. Each of its endless loops ends after the first item.
    real_receiver = goose.Receiver
    receivers = []

    def receiver(link):
        receivers.append(real_receiver(rx))
        return receivers[-1]

    monkeypatch.setattr(goose, "Receiver", receiver)
    events = []

    def fake_print(*args):
        events.append(args)
        for s in list(receivers[0]._subs):
            s.close()

    sv = goose.SvPublisher(sv_tx, goose.SvPublisherConfig(sv_id="MU01"))
    sample = goose.LeSamples.from_measurements(currents=(1.0, 2.0, 3.0, 0.0), voltages=(0.0, 0.0, 0.0, 0.0))
    loop = asyncio.get_running_loop()

    def push():
        sv.push(sample)
        for s in list(receivers[0]._subs) if receivers else ():
            if isinstance(s, goose.SvSubscriber) and s.stats.samples > 0:
                s.close()
                return
        loop.call_later(0.005, push)

    loop.call_later(0.005, push)
    await asyncio.wait_for(run_block(4, {"iec": iec, "print": fake_print}), 5)
    assert events[0][1] in (1, 2)  # the link may have queued the first state
