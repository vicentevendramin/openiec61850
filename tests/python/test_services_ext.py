"""Setting groups, logs, files and GoCBs: Python server <-> Python client over loopback."""

import asyncio
import errno
import io
import threading
from datetime import datetime, timezone

import pytest

import openiec61850 as iec
from openiec61850 import FC, BasicType as B, TrgOps, sync

from conftest import FAST

LD = "IED1LD0"
SET_MAG = f"{LD}/PTOC1.StrVal.setMag.f[SG]"
SET_MAG_SE = f"{LD}/PTOC1.StrVal.setMag.f[SE]"
IND = f"{LD}/GGIO1.Ind1.stVal[ST]"
LOG = f"{LD}/LLN0.EventLog"
LCB = f"{LD}/LLN0.lcb01[LG]"
GCB = f"{LD}/LLN0.gcb01[GO]"


def make_model(resv_tms=0):
    b = iec.ModelBuilder()
    ld = b.logical_device(LD)
    lln0 = ld.logical_node("LLN0")
    lln0.data_object("Mod").attribute("stVal", FC.ST, B.ENUMERATED, value=1)
    ptoc = ld.logical_node("PTOC1")
    (
        ptoc.data_object("StrVal")
        .structure("setMag", FC.SG)
        .attribute("f", B.FLOAT32, triggers=TrgOps.DATA_CHANGE)
        .group_value(1, 1.0)
        .group_value(2, 2.0)
        .group_value(3, 3.0)
    )
    ggio = ld.logical_node("GGIO1")
    ind = ggio.data_object("Ind1")
    ind.attribute("stVal", FC.ST, B.BOOLEAN, triggers=TrgOps.DATA_CHANGE)
    ind.attribute("q", FC.ST, B.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
    ind.attribute("t", FC.ST, B.TIMESTAMP)
    lln0.setting_group_control(num_of_sgs=3, act_sg=1, resv_tms=resv_tms)
    lln0.data_set("DSLOG", [IND])
    lln0.data_set("DSSG", [SET_MAG])
    lln0.log("EventLog")
    lln0.log_control(
        iec.LogControl(
            "lcb01",
            data_set="DSLOG",
            log_name="EventLog",
            log_ena=True,
            trg_ops=TrgOps.DATA_CHANGE | TrgOps.INTEGRITY,
        )
    )
    lln0.goose_control(
        iec.GooseControl("gcb01", go_id="GO1", data_set="DSLOG", app_id=0x1000, min_time=4, max_time=1000)
    )
    return b.build()


async def wait_for(pred, timeout=5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        r = pred()
        if asyncio.iscoroutine(r):
            r = await r
        if r:
            return r
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


def test_model_views():
    m = make_model()
    (ln, sg), = m.setting_group_controls
    assert str(ln) == f"{LD}/LLN0" and sg == iec.SettingGroupControl(3, 1, 0)
    assert [str(r) for r in m.logs] == [LOG]
    (_, lc), = m.log_controls
    assert lc.name == "lcb01" and lc.log_name == "EventLog" and lc.log_ena
    assert TrgOps.INTEGRITY in lc.trg_ops
    (_, gc), = m.goose_controls
    assert gc.go_id == "GO1" and gc.app_id == 0x1000 and gc.dst_mac == "01-0C-CD-01-00-00"


def test_builder_group_value_out_of_range():
    b = iec.ModelBuilder()
    ld = b.logical_device(LD)
    ld.logical_node("LLN0").setting_group_control(num_of_sgs=2)
    ld.logical_node("PTOC1").data_object("StrVal").attribute("v", FC.SG, B.FLOAT32).group_value(3, 1.0)
    with pytest.raises(iec.Iec61850Error):
        b.build()


async def test_setting_groups():
    events = []

    def on_sg(e):
        events.append(e)
        if e.action == iec.SettingGroupAction.SELECT_ACTIVE and e.group == 3 and len(events) == 1:
            return iec.DataAccessError.TEMPORARILY_UNAVAILABLE
        return None

    async with await iec.Server.start(make_model(), "127.0.0.1", 0, on_setting_group=on_sg) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            v = await c.sgcb_values(LD)
            assert (v.num_of_sgs, v.act_sg, v.edit_sg, v.cnf_edit) == (3, 1, 0, False)
            assert await c.read(SET_MAG) == pytest.approx(1.0)

            with pytest.raises(iec.TemporarilyUnavailable):
                await c.select_active_sg(LD, 3)  # refused by the hook
            await c.select_active_sg(LD, 2)
            assert await c.read(SET_MAG) == pytest.approx(2.0)
            v = await c.sgcb_values(LD)
            assert v.act_sg == 2 and isinstance(v.lact_tm, iec.Timestamp)
            with pytest.raises(iec.ValueInvalid):
                await c.select_active_sg(LD, 4)
            assert events[1] == iec.SettingGroupEvent(events[1].association, LD, iec.SettingGroupAction.SELECT_ACTIVE, 2)

            with pytest.raises(iec.TemporarilyUnavailable):
                await c.set_edit_sg_value(SET_MAG_SE, 9.0)  # no SelectEditSG
            await c.select_edit_sg(LD, 3)
            assert await c.edit_sg_value(SET_MAG_SE) == pytest.approx(3.0)
            await c.set_edit_sg_value(SET_MAG_SE, 3.5)  # plain float typed from the definition
            assert await c.edit_sg_value(SET_MAG_SE) == pytest.approx(3.5)
            assert await c.read(SET_MAG) == pytest.approx(2.0)
            await c.confirm_edit_sg_values(LD)
            assert await srv.read_setting_group(SET_MAG, 3) == pytest.approx(3.5)
            assert await srv.read_setting_group(SET_MAG, 2) == pytest.approx(2.0)
            assert [e.action for e in events[-2:]] == [
                iec.SettingGroupAction.SELECT_EDIT,
                iec.SettingGroupAction.CONFIRM_EDIT,
            ]
            await c.select_edit_sg(LD, 0)

            srv.select_active_setting_group(LD, 3)
            assert await wait_for(lambda: _approx(c.read(SET_MAG), 3.5))
            with pytest.raises(iec.ValueOutOfRange):
                srv.select_active_setting_group(LD, 9)
            with pytest.raises(iec.ObjectNotFound):
                srv.select_active_setting_group("NOPE", 1)


async def _approx(aw, v):
    return abs(await aw - v) < 1e-6


async def test_logs():
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, log_capacity=5) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            assert await c.query_log_by_time(LOG) == []
            srv.update(IND, True)
            srv.update(IND, False)
            await wait_for(lambda: _eq(c.log_status(LOG), 2))
            entries = await c.query_log_by_time(LOG)
            assert len(entries) == 2
            first, second = entries
            assert isinstance(first.entry_id, iec.EntryID) and isinstance(first.time, iec.EntryTime)
            (d,) = first.data
            assert d.reference == f"{LD}/GGIO1$ST$Ind1$stVal"
            assert str(d.object_reference) == IND
            assert d.value is True and d.reason == TrgOps.DATA_CHANGE
            assert second.values() == {d.reference: False}

            v = await c.lcb_values(LCB)
            assert v.log_ena is True
            assert v.log_ref == f"{LD}/LLN0$EventLog"
            assert v.dat_set == f"{LD}/LLN0$DSLOG" and str(v.data_set) == f"{LD}/LLN0.DSLOG"
            assert v.old_ent == first.entry_id and v.new_ent == second.entry_id
            assert v.new_entr_tm == second.time
            assert v.trg_ops == TrgOps.DATA_CHANGE | TrgOps.INTEGRITY

            after = await c.query_log_after(LOG, first.time, first.entry_id)
            assert [e.entry_id for e in after] == [second.entry_id]
            assert await c.query_log_by_time(LOG, start=second.time)
            assert [e.entry_id async for e in c.log_entries(LOG)] == [first.entry_id, second.entry_id]
            dt = datetime.now(timezone.utc)
            assert await c.query_log_by_time(LOG, start=dt.replace(year=dt.year + 1)) == []

            for i in range(8):
                srv.update(IND, i % 2 == 0)
            await wait_for(lambda: _eq(c.log_status(LOG), 5))  # bounded

            await c.set_lcb_values(LCB, log_ena=False)
            await c.set_lcb_values(LCB, iec.LcbSettings(dat_set=f"{LD}/LLN0.DSSG", log_ena=True))
            v = await c.lcb_values(LCB)
            assert v.dat_set == f"{LD}/LLN0$DSSG" and v.log_ena
            with pytest.raises(iec.TemporarilyUnavailable):
                await c.set_lcb_values(LCB, dat_set=f"{LD}/LLN0.DSLOG")  # locked while enabled
            with pytest.raises(iec.ObjectNotFound):
                await c.query_log_by_time(f"{LD}/LLN0.NoLog")
            with pytest.raises(iec.InvalidOperation):
                await c.lcb_values(GCB)


async def _eq(aw, v):
    return await aw == v


async def test_gocb():
    states = []
    async_states = []

    async def on_gc(state):
        await asyncio.sleep(0)
        async_states.append(state)

    def hook(state):
        states.append(state)
        return on_gc(state)

    async with await iec.Server.start(make_model(), "127.0.0.1", 0, on_goose_control=hook) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            v = await c.gocb_values(GCB)
            assert v.go_ena is False and v.go_id == "GO1" and v.conf_rev == 1
            assert v.dat_set == f"{LD}/LLN0$DSLOG" and str(v.data_set) == f"{LD}/LLN0.DSLOG"
            assert v.dst_address == iec.GooseAddress(bytes.fromhex("010CCD010000"), 4, 0, 0x1000)
            assert v.dst_address.mac_text == "01-0C-CD-01-00-00"
            assert (v.min_time, v.max_time, v.fixed_offs) == (4, 1000, False)

            await c.set_gocb_values(GCB, go_id="GO2", dat_set=f"{LD}/LLN0.DSSG", go_ena=True)
            await wait_for(lambda: len(async_states) == 3)
            last = states[-1]
            assert last.go_ena and last.go_id == "GO2" and last.conf_rev == 2
            assert [str(m) for m in last.members] == [SET_MAG]
            assert str(last.reference) == GCB
            with pytest.raises(iec.TemporarilyUnavailable):
                await c.set_gocb_values(GCB, iec.GoCBSettings(go_id="GO3"))

            st = await srv.goose_control(GCB)
            assert st.go_ena and st.app_id == 0x1000 and st.dst_mac == "01-0C-CD-01-00-00"
            assert [s.reference for s in await srv.goose_controls()] == [st.reference]
            with pytest.raises(iec.ObjectNotFound):
                await srv.goose_control(f"{LD}/LLN0.nope[GO]")
            with pytest.raises(iec.InvalidOperation):
                await c.gocb_values(f"{LD}/LLN0.gcb01[LG]")


BIG = bytes((i * 7) & 0xFF for i in range(200_000))


def memory_store():
    store = iec.MemoryFileStore()
    store.put("COMTRADE/fault1.cfg", b"cfg")
    store.put("COMTRADE/fault1.dat", BIG)
    store.put("readme.txt", b"hi", modified=datetime.fromtimestamp(1_700_000_000, timezone.utc))
    return store


async def check_file_services(store, c, tmp_path):
    files = await c.list_files()
    assert [f.name for f in files] == ["COMTRADE/fault1.cfg", "COMTRADE/fault1.dat", "readme.txt"]
    assert files[1].size == len(BIG)
    assert files[2].last_modified == datetime.fromtimestamp(1_700_000_000, timezone.utc)
    assert len(await c.list_files("COMTRADE")) == 2

    assert await c.read_file("readme.txt") == b"hi"
    progress = []
    n = await c.download_file("/COMTRADE/fault1.dat", tmp_path / "f.dat", on_chunk=progress.append)
    assert n == len(BIG) and (tmp_path / "f.dat").read_bytes() == BIG
    assert len(progress) > 1 and progress[-1] == len(BIG)
    buf = io.BytesIO()
    assert await c.download_file("COMTRADE/fault1.cfg", buf) == 3 and buf.getvalue() == b"cfg"

    with pytest.raises(iec.FileError) as e:
        await c.read_file("nope.txt")
    assert e.value.file_error == iec.FileErrorCode.FILE_NON_EXISTENT
    assert e.value.error_class == iec.ErrorClass.FILE
    with pytest.raises(iec.FileError):
        await c.download_file("nope.txt", tmp_path / "nope")
    assert not (tmp_path / "nope").exists()  # removed on failure
    with pytest.raises(iec.FileError) as e:
        await c.read_file("../etc/passwd")
    assert e.value.file_error == iec.FileErrorCode.FILENAME_SYNTAX_ERROR

    await c.rename_file("readme.txt", "README")
    with pytest.raises(iec.FileError) as e:
        await c.rename_file("README", "COMTRADE/fault1.cfg")
    assert e.value.file_error == iec.FileErrorCode.DUPLICATE_FILENAME
    await c.delete_file("README")
    with pytest.raises(iec.FileError) as e:
        await c.delete_file("README")
    assert e.value.file_error == iec.FileErrorCode.FILE_NON_EXISTENT
    assert [f.name for f in store.list()] == ["COMTRADE/fault1.cfg", "COMTRADE/fault1.dat"]


async def test_files_memory_store(tmp_path):
    store = memory_store()
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store, max_open_files=2) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            await check_file_services(store, c, tmp_path)
    assert store.get("README") is None and store.get("COMTRADE/fault1.cfg") == b"cfg"
    with pytest.raises(iec.FileStoreError) as e:
        store.put("../x", b"")
    assert e.value.errno == errno.EINVAL
    with pytest.raises(iec.FileStoreError) as e:
        store.stat("missing")
    assert e.value.errno == errno.ENOENT


async def test_no_file_store():
    async with await iec.Server.start(make_model(), "127.0.0.1", 0) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            with pytest.raises(iec.RequestRejected):
                await c.list_files()


async def test_directory_store(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.txt").write_bytes(b"hello")
    (tmp_path / "secret.txt").write_bytes(b"secret")
    store = iec.DirectoryFileStore(root)
    assert [f.name for f in store.list()] == ["sub/a.txt"]
    assert store.read("sub/a.txt", 1, 16) == b"ello"
    with pytest.raises(iec.InvalidOperation):
        iec.DirectoryFileStore(tmp_path / "missing")
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            assert await c.read_file("sub/a.txt") == b"hello"
            with pytest.raises(iec.FileError):
                await c.read_file("../secret.txt")
            await c.rename_file("sub/a.txt", "b.txt")
            assert (root / "b.txt").exists()
            await c.delete_file("b.txt")
            assert not (root / "b.txt").exists()


class DictStore(iec.FileStore):
    """A Python file store; records the thread it is called on."""

    def __init__(self, files):
        self.files = dict(files)
        self.threads = set()

    def _seen(self):
        self.threads.add(threading.get_ident())

    def list(self, directory):
        self._seen()
        names = sorted(n for n in self.files if not directory or n == directory or n.startswith(directory + "/"))
        if directory and not names:
            raise FileNotFoundError(directory)
        return [iec.FileInfo(n, len(self.files[n])) for n in names]

    def stat(self, path):
        self._seen()
        if path not in self.files:
            raise FileNotFoundError(path)
        return iec.FileInfo(path, len(self.files[path]), datetime.fromtimestamp(1_600_000_000, timezone.utc))

    def read(self, path, offset, size):
        self._seen()
        if path == "boom":
            raise RuntimeError("unexpected")
        return self.files[path][offset : offset + size]

    def remove(self, path):
        self._seen()
        if path == "locked":
            raise PermissionError(path)
        del self.files[path]

    def rename(self, current, new):
        self._seen()
        if new in self.files:
            raise FileExistsError(new)
        self.files[new] = self.files.pop(current)


async def test_python_file_store(caplog):
    store = DictStore({"a.bin": BIG, "locked": b"x", "boom": b"y"})
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            assert [f.name for f in await c.list_files()] == ["a.bin", "boom", "locked"]
            assert await c.read_file("a.bin") == BIG
            with pytest.raises(iec.FileError) as e:
                await c.delete_file("locked")
            assert e.value.file_error == iec.FileErrorCode.FILE_ACCESS_DENIED
            with pytest.raises(iec.FileError) as e:
                await c.rename_file("a.bin", "locked")
            assert e.value.file_error == iec.FileErrorCode.DUPLICATE_FILENAME
            with pytest.raises(iec.FileError) as e:
                await c.read_file("boom")
            assert e.value.file_error == iec.FileErrorCode.OTHER
            await c.rename_file("a.bin", "b.bin")
            assert "b.bin" in store.files
    assert threading.get_ident() not in store.threads  # called on the I/O thread
    assert "file store read failed" in caplog.text

    with pytest.raises(TypeError):
        await iec.Server.start(make_model(), "127.0.0.1", 0, files=object())


def test_sync_facade(tmp_path):
    with sync.Server.start(make_model(), "127.0.0.1", 0, files=memory_store()) as srv:
        with sync.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            assert c.sgcb_values(LD).num_of_sgs == 3
            c.select_active_sg(LD, 2)
            assert c.read(SET_MAG) == pytest.approx(2.0)
            c.select_edit_sg(LD, 1)
            c.set_edit_sg_value(SET_MAG_SE, 1.25)
            assert c.edit_sg_value(SET_MAG_SE) == pytest.approx(1.25)
            c.confirm_edit_sg_values(LD)
            assert srv.read_setting_group(SET_MAG, 1) == pytest.approx(1.25)
            srv.select_active_setting_group(LD, 1)

            srv.update(IND, True)
            deadline = 50
            while c.log_status(LOG) < 1 and deadline:
                deadline -= 1
                threading.Event().wait(0.05)
            (entry,) = c.query_log_by_time(LOG)
            assert c.query_log_after(LOG, entry.time, entry.entry_id) == []
            assert c.lcb_values(LCB).log_ena
            c.set_lcb_values(LCB, log_ena=False)

            assert c.gocb_values(GCB).go_id == "GO1"
            c.set_gocb_values(GCB, go_ena=True)
            assert srv.goose_control(GCB).go_ena
            assert len(srv.goose_controls()) == 1

            assert len(c.list_files()) == 3
            assert c.read_file("readme.txt") == b"hi"
            assert c.download_file("COMTRADE/fault1.dat", tmp_path / "x") == len(BIG)
            c.rename_file("readme.txt", "r2")
            c.delete_file("r2")
            assert len(c.list_files()) == 2


# --- SetFile (MMS ObtainFile)


def _accept(event):
    return None


async def test_set_file_is_off_without_the_hook():
    store = iec.MemoryFileStore()
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port) as c:
            with pytest.raises(iec.RequestRejected):
                await c.write_file("a", b"x")


async def test_set_file_into_memory_store(tmp_path):
    store = iec.MemoryFileStore()
    seen = []
    big = bytes(i % 251 for i in range(100_000))
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store, on_obtain_file=seen.append) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            await c.write_file("fw/image.bin", big)
            assert store.get("fw/image.bin") == big
            assert seen == [iec.ObtainFileEvent(seen[0].association, "fw/image.bin", "fw/image.bin")]

            path = tmp_path / "local.bin"
            path.write_bytes(b"from disk")
            assert await c.upload_file("disk.bin", path) == 9
            assert store.get("disk.bin") == b"from disk"

            assert await c.upload_file("obj.bin", io.BytesIO(b"object"), source_name="local") == 6
            assert store.get("obj.bin") == b"object"
            assert seen[-1].source == "local"

            with pytest.raises(iec.FileError) as e:
                await c.write_file("obj.bin", b"again")
            assert e.value.file_error == iec.FileErrorCode.DUPLICATE_FILENAME
            with pytest.raises(iec.FileError) as e:
                await c.write_file("../evil", b"x")
            assert e.value.file_error == iec.FileErrorCode.FILENAME_SYNTAX_ERROR
            assert await c.read_file("obj.bin") == b"object"


async def test_set_file_directory_store(tmp_path):
    store = iec.DirectoryFileStore(tmp_path)
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store, on_obtain_file=_accept) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            await c.write_file("sub/dir/a.bin", b"abc")
    assert (tmp_path / "sub/dir/a.bin").read_bytes() == b"abc"
    store.write("local.bin", b"x")
    assert (tmp_path / "local.bin").read_bytes() == b"x"
    with pytest.raises(iec.FileStoreError) as e:
        store.write("local.bin", b"y")
    assert e.value.errno == errno.EEXIST


async def test_set_file_refused():
    store = iec.MemoryFileStore()

    def hook(event):
        if event.destination.startswith("locked/"):
            return False
        if event.destination.startswith("full/"):
            return iec.FileErrorCode.INSUFFICIENT_SPACE_IN_FILESTORE
        if event.destination.startswith("broken/"):
            raise RuntimeError("expected by the test")
        return None

    async with await iec.Server.start(
        make_model(), "127.0.0.1", 0, files=store, on_obtain_file=hook, max_obtain_file_size=10
    ) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            for name, code in (
                ("locked/a", iec.FileErrorCode.FILE_ACCESS_DENIED),
                ("broken/a", iec.FileErrorCode.FILE_ACCESS_DENIED),
                ("full/a", iec.FileErrorCode.INSUFFICIENT_SPACE_IN_FILESTORE),
            ):
                with pytest.raises(iec.FileError) as e:
                    await c.write_file(name, b"x")
                assert e.value.file_error == code
            with pytest.raises(iec.FileError) as e:
                await c.write_file("big", bytes(11))
            assert e.value.file_error == iec.FileErrorCode.INSUFFICIENT_SPACE_IN_FILESTORE
            await c.write_file("fits", bytes(10))
            assert store.get("big") is None and store.get("fits") == bytes(10)


async def test_set_file_needs_a_writable_store():
    class ReadOnly(iec.FileStore):
        def list(self, directory):
            return []

        def stat(self, path):
            raise FileNotFoundError(path)

        def read(self, path, offset, size):
            return b""

        def remove(self, path):
            raise PermissionError(path)

        def rename(self, current, new):
            raise PermissionError(current)

    for files in (None, ReadOnly()):
        async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=files, on_obtain_file=_accept) as srv:
            async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
                with pytest.raises(iec.Iec61850Error):
                    await c.write_file("a", b"x")


async def test_set_file_python_store_and_failing_source():
    class Dict(iec.FileStore):
        def __init__(self):
            self.files = {}

        def list(self, directory):
            return [iec.FileInfo(k, len(v)) for k, v in sorted(self.files.items())]

        def stat(self, path):
            if path not in self.files:
                raise FileNotFoundError(path)
            return iec.FileInfo(path, len(self.files[path]))

        def read(self, path, offset, size):
            return self.files[path][offset : offset + size]

        def remove(self, path):
            del self.files[path]

        def rename(self, current, new):
            self.files[new] = self.files.pop(current)

        def write(self, path, content):
            if path == "nospace":
                raise OSError(errno.ENOSPC, "full")
            self.files[path] = content

    class Broken(io.BytesIO):
        def read(self, *a):
            raise OSError("expected by the test")

    store = Dict()
    async with await iec.Server.start(make_model(), "127.0.0.1", 0, files=store, on_obtain_file=_accept) as srv:
        async with await iec.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            await c.write_file("a.bin", b"payload")
            assert store.files == {"a.bin": b"payload"}
            with pytest.raises(iec.FileError) as e:
                await c.write_file("nospace", b"x")
            assert e.value.file_error == iec.FileErrorCode.INSUFFICIENT_SPACE_IN_FILESTORE
            with pytest.raises(OSError, match="expected by the test"):
                await c.upload_file("b.bin", Broken(b"data"))
            assert "b.bin" not in store.files
            await c.write_file("c.bin", b"still fine")


def test_set_file_sync(tmp_path):
    store = iec.MemoryFileStore()
    path = tmp_path / "f.bin"
    path.write_bytes(b"sync file")
    with sync.Server.start(make_model(), "127.0.0.1", 0, files=store, on_obtain_file=_accept) as srv:
        with sync.Client.connect("127.0.0.1", srv.port, **FAST) as c:
            c.write_file("a", b"sync")
            assert c.upload_file("b", path) == 9
            assert c.read_file("b") == b"sync file"
    assert store.get("a") == b"sync"
