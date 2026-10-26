"""IEC 61850 server over MMS (asyncio API).

Build a :class:`Model` with :class:`ModelBuilder` (or load it from SCL with
:meth:`Model.from_scl`), then serve it::

    b = ModelBuilder()
    ln = b.logical_device("IED1LD0").logical_node("GGIO1")
    ind = ln.data_object("Ind1")
    ind.attribute("stVal", FC.ST, BasicType.BOOLEAN, triggers=TrgOps.DATA_CHANGE)
    ind.attribute("q", FC.ST, BasicType.QUALITY, triggers=TrgOps.QUALITY_CHANGE)
    ind.attribute("t", FC.ST, BasicType.TIMESTAMP)
    model = b.build()

    async with await Server.start(model, port=0) as server:
        server.update("IED1LD0/GGIO1.Ind1.stVal", True)

Values are plain Python values typed from the model (``True``, ``3``, ``1.5``, ``"text"``,
:class:`Quality`, :class:`Timestamp`, ``[..]`` / ``{..}`` for structures and arrays...), with the
conversion rules of ``openiec61850._values``.

Application hooks
-----------------

The native server calls its hooks on its I/O thread and needs the answer of ``on_write``,
``authorize`` and of a Select / Cancel at once. The Python hooks are therefore called on that
thread (holding the GIL only for the call): they must be quick and must never block, in
particular never wait for the asyncio loop or for a blocking :mod:`openiec61850.sync` call. A hook
may be ``async def`` as long as it does not suspend for these answers (it is driven to its first
suspension point synchronously; a hook that suspends is treated as a failure).

An Operate can take as long as it needs: ``on_control`` may return an awaitable (e.g. be an
``async def`` hook), which is then run as a task on the event loop the server was started from
while the client gets a positive Write response; its result (a :class:`ControlResult`) completes
the operation (CommandTermination with enhanced security, LastApplError for a refusal).
Alternatively the hook returns :meth:`ControlResult.pending` and calls
:meth:`ControlRequest.complete` later, from any thread.

``on_setting_group`` answers at once like ``on_write``. ``on_goose_control`` needs no answer: it is
scheduled on the event loop (it may be ``async def``).

File stores
-----------

``Server.start(files=...)`` serves the MMS file services from a :class:`MemoryFileStore`, a
:class:`DirectoryFileStore` (both native: no Python code runs per request) or a subclass of
:class:`FileStore`. The methods of a Python store are called synchronously on the I/O thread
for each FileOpen / FileRead / FileDirectory / FileDelete / FileRename, holding the GIL only for
the call: they must be quick (a read returns at most ``size`` octets) and must never wait for the
event loop or a blocking :mod:`openiec61850.sync` call.

Exceptions raised by hooks are logged on the ``openiec61850.server`` logger; the write or command
is then refused.
"""

from __future__ import annotations

import asyncio
import enum
import inspect
import logging
import os
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import errno
from datetime import datetime, timezone
from typing import Any, Union

from openiec61850 import _core
from openiec61850._client import DataDefinition
from openiec61850._control import AddCause, Originator, add_cause
from openiec61850._errors import FileStoreError, InvalidOperation, ObjectNotFound, SclError, ServiceError
from openiec61850._types import (
    FC,
    BasicType,
    Check,
    CtlModel,
    Edition,
    ObjectReference,
    OptFlds,
    OrCat,
    Quality,
    Timestamp,
    TrgOps,
)
from openiec61850._values import TypeSpec, decode, encode, spec_from_definition

__all__ = [
    "AssociationRequest",
    "ControlAction",
    "ControlRequest",
    "ControlResult",
    "DataAccessError",
    "DataSetDefinition",
    "DirectoryFileStore",
    "FileInfo",
    "FileStore",
    "GooseControl",
    "GooseControlState",
    "Identity",
    "LogControl",
    "MemoryFileStore",
    "SettingGroupAction",
    "SettingGroupControl",
    "SettingGroupEvent",
    "LogicalDeviceBuilder",
    "LogicalNodeBuilder",
    "DataObjectBuilder",
    "AttributeBuilder",
    "Model",
    "ModelBuilder",
    "ModelNode",
    "NodeKind",
    "ReportControl",
    "SclDiagnostic",
    "Server",
]

_log = logging.getLogger("openiec61850.server")

Ref = Union[str, ObjectReference]


def _text(r: Ref) -> str:
    return r.text if isinstance(r, ObjectReference) else str(r)


class DataAccessError(enum.IntEnum):
    """MMS DataAccessError (ISO 9506-2), returned by ``on_write`` to refuse a write."""

    OBJECT_INVALIDATED = 0
    HARDWARE_FAULT = 1
    TEMPORARILY_UNAVAILABLE = 2
    OBJECT_ACCESS_DENIED = 3
    OBJECT_UNDEFINED = 4
    INVALID_ADDRESS = 5
    TYPE_UNSUPPORTED = 6
    TYPE_INCONSISTENT = 7
    OBJECT_ATTRIBUTE_INCONSISTENT = 8
    OBJECT_ACCESS_UNSUPPORTED = 9
    OBJECT_NON_EXISTENT = 10
    OBJECT_VALUE_INVALID = 11


class NodeKind(str, enum.Enum):
    LOGICAL_DEVICE = "logical_device"
    LOGICAL_NODE = "logical_node"
    DATA_OBJECT = "data_object"
    CONTROL_BLOCK = "control_block"
    DATA_ATTRIBUTE = "data_attribute"


@dataclass(frozen=True)
class SclDiagnostic:
    """A problem found while loading an SCL file."""

    level: str  # "warning" or "error"
    code: str  # e.g. "unknown_type", "invalid_value"
    line: int  # 1-based, 0 when unknown
    message: str

    def __str__(self) -> str:
        where = f"line {self.line}: " if self.line else ""
        return f"{where}{self.level}: {self.code}: {self.message}"


@dataclass(frozen=True)
class ReportControl:
    """A BRCB / URCB of the model (IEC 61850-7-2 §17.2). ``data_set`` names a data set of the
    same LN ("" for none); ``buf_tm`` and ``intg_pd`` are in milliseconds."""

    name: str
    buffered: bool = False
    rpt_id: str = ""
    data_set: str = ""
    conf_rev: int = 1
    opt_flds: OptFlds = OptFlds(0)
    buf_tm: int = 0
    trg_ops: TrgOps = TrgOps(0)
    intg_pd: int = 0

    def _native(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "buffered": bool(self.buffered),
            "rpt_id": self.rpt_id,
            "data_set": self.data_set,
            "conf_rev": int(self.conf_rev),
            "opt_flds": int(self.opt_flds),
            "buf_tm": int(self.buf_tm),
            "trg_ops": int(self.trg_ops),
            "intg_pd": int(self.intg_pd),
        }


@dataclass(frozen=True)
class SettingGroupControl:
    """The setting group control block "SGCB" of an LD (IEC 61850-7-2 §16; LLN0 only).

    ``resv_tms`` (Ed.2): seconds an edit selection stays reserved without activity (0: until
    released or the association ends)."""

    num_of_sgs: int = 1
    act_sg: int = 1
    resv_tms: int = 0


@dataclass(frozen=True)
class LogControl:
    """A log control block (IEC 61850-7-2 §17.3.3). ``data_set`` names a data set of the same LN;
    ``log_name`` a log declared with :meth:`LogicalNodeBuilder.log` in LN ``log_ln`` of the same
    LD ("" for this LN); ``intg_pd`` in milliseconds."""

    name: str
    data_set: str = ""
    log_name: str = ""
    log_ln: str = ""
    log_ena: bool = False
    trg_ops: TrgOps = TrgOps(0)
    intg_pd: int = 0

    def _native(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "data_set": self.data_set,
            "log_name": self.log_name,
            "log_ln": self.log_ln,
            "log_ena": bool(self.log_ena),
            "trg_ops": int(self.trg_ops),
            "intg_pd": int(self.intg_pd),
        }


def _mac_bytes(mac: str | bytes) -> bytes:
    if isinstance(mac, (bytes, bytearray)):
        b = bytes(mac)
    else:
        text = mac.replace("-", "").replace(":", "")
        b = bytes.fromhex(text)
    if len(b) != 6:
        raise ValueError(f"a MAC address has 6 octets: {mac!r}")
    return b


def _mac_text(b: bytes) -> str:
    return "-".join(f"{x:02X}" for x in b)


@dataclass(frozen=True)
class GooseControl:
    """A GOOSE control block (IEC 61850-7-2 §18.2, SCL GSEControl + GSE address). The server
    exposes it as MMS variables; publishing is done with :mod:`openiec61850.goose`. ``min_time``
    / ``max_time`` in milliseconds; ``dst_mac`` as "01-0C-CD-01-00-00" or 6 octets."""

    name: str
    go_id: str = ""
    data_set: str = ""
    conf_rev: int = 1
    go_ena: bool = False
    dst_mac: str | bytes = "01-0C-CD-01-00-00"
    vlan_priority: int = 4
    vlan_id: int = 0
    app_id: int = 0
    min_time: int = 0
    max_time: int = 0
    fixed_offs: bool = False

    def _native(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "go_id": self.go_id,
            "data_set": self.data_set,
            "conf_rev": int(self.conf_rev),
            "go_ena": bool(self.go_ena),
            "dst_mac": _mac_bytes(self.dst_mac),
            "vlan_priority": int(self.vlan_priority),
            "vlan_id": int(self.vlan_id),
            "app_id": int(self.app_id),
            "min_time": int(self.min_time),
            "max_time": int(self.max_time),
            "fixed_offs": bool(self.fixed_offs),
        }

    @staticmethod
    def _from(d: Mapping[str, Any]) -> GooseControl:
        return GooseControl(
            name=d["name"],
            go_id=d["go_id"],
            data_set=d["data_set"],
            conf_rev=d["conf_rev"],
            go_ena=d["go_ena"],
            dst_mac=_mac_text(d["dst_mac"]),
            vlan_priority=d["vlan_priority"],
            vlan_id=d["vlan_id"],
            app_id=d["app_id"],
            min_time=d["min_time"],
            max_time=d["max_time"],
            fixed_offs=d["fixed_offs"],
        )


@dataclass(frozen=True)
class DataSetDefinition:
    """A data set defined by the model (persistent)."""

    reference: ObjectReference  # LD/LN.name
    members: tuple[ObjectReference, ...]


# ---------------------------------------------------------------------------------------------
# Model


class ModelNode:
    """Read-only view of one node of a :class:`Model`."""

    __slots__ = ("_model", "_id", "_info")

    def __init__(self, model: Model, node_id: int) -> None:
        self._model = model
        self._id = node_id
        self._info = model._native.node(node_id)

    @property
    def id(self) -> int:
        return self._id

    @property
    def name(self) -> str:
        return self._info[0]

    @property
    def kind(self) -> NodeKind:
        return NodeKind(self._info[1])

    @property
    def parent(self) -> ModelNode | None:
        p = self._info[2]
        return ModelNode(self._model, p) if p is not None else None

    @property
    def children(self) -> tuple[ModelNode, ...]:
        return tuple(ModelNode(self._model, c) for c in self._info[3])

    def child(self, name: str) -> ModelNode | None:
        for c in self.children:
            if c.name == name:
                return c
        return None

    @property
    def fc(self) -> FC | None:
        return FC(self._info[4]) if self._info[4] is not None else None

    @property
    def basic_type(self) -> BasicType | None:
        return BasicType(self._info[5]) if self._info[5] is not None else None

    @property
    def size(self) -> int:
        return self._info[6]

    @property
    def count(self) -> int:
        """Number of elements of an array attribute (0: not an array)."""
        return self._info[7]

    @property
    def triggers(self) -> TrgOps:
        dchg, qchg, dupd = self._info[8]
        t = TrgOps(0)
        if dchg:
            t |= TrgOps.DATA_CHANGE
        if qchg:
            t |= TrgOps.QUALITY_CHANGE
        if dupd:
            t |= TrgOps.DATA_UPDATE
        return t

    @property
    def reference(self) -> str:
        """The ACSI reference ``LD/LN.DO.DA``."""
        return self._model._native.reference_of(self._id)

    @property
    def initial_value(self) -> Any:
        """The initial value of a leaf or array attribute (None otherwise)."""
        t = self._model._native.initial_value(self._id)
        if t is None:
            return None
        return decode(t, spec_from_definition(self._model._native.node_definition(self._id)))

    def definition(self, fc: FC | str | None = None) -> DataDefinition:
        """The type of the node seen under ``fc`` (like :meth:`Client.data_definition`)."""
        return DataDefinition._from(self._model._native.node_definition(self._id, None if fc is None else str(fc)))

    def __repr__(self) -> str:
        return f"ModelNode({self.reference!r}, {self.kind.value})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ModelNode) and other._model is self._model and other._id == self._id

    def __hash__(self) -> int:
        return hash((id(self._model), self._id))


class Model:
    """An immutable server data model (IEC 61850-7-2 §6 - §9 and its MMS view, 8-1 §8 - §9).

    Built with :class:`ModelBuilder` or loaded with :meth:`from_scl`; a model can be served by
    several servers.
    """

    def __init__(self, native: Any, diagnostics: Sequence[SclDiagnostic] = ()) -> None:
        """Internal; use :class:`ModelBuilder` or :meth:`from_scl`."""
        self._native = native
        self._edition = Edition(native.edition)
        self._diagnostics = tuple(diagnostics)
        self._specs: dict[str, TypeSpec | None] = {}

    @classmethod
    def from_scl(
        cls,
        source: str | os.PathLike[str] | bytes,
        ied: str | None = None,
        access_point: str | None = None,
        *,
        strict: bool = False,
        setting_group: int = 0,
    ) -> Model:
        """The model of one IED access point of an SCL file (ICD / IID / CID / SCD).

        ``source`` is a path, or the SCL text itself (a ``str`` starting with ``<`` or
        ``bytes``). ``ied`` / ``access_point`` default to the first IED and the first access point
        with a server. In lenient mode (default) what cannot be mapped is skipped and reported in
        :attr:`diagnostics`; ``strict=True`` fails instead. ``setting_group`` selects the values
        of FC SG / SE attributes (0: the SettingControl actSG). Raises :class:`SclError` (with
        ``diagnostics``) when no model can be built.
        """
        if isinstance(source, (bytes, bytearray)):
            text, is_text = bytes(source).decode("utf-8"), True
        elif isinstance(source, str) and source.lstrip().startswith("<"):
            text, is_text = source, True
        else:
            text, is_text = os.fspath(source), False
        native, diags, error = _core.Model.load_scl(
            text, is_text, ied or "", access_point or "", bool(strict), int(setting_group)
        )
        diagnostics = tuple(SclDiagnostic(*d) for d in diags)
        if native is None:
            exc = SclError(
                f"cannot load the SCL model: {error}"
                + "".join(f"\n  {d}" for d in diagnostics if d.level == "error")[:4000],
                category=getattr(error, "category", None),
                code=getattr(error, "code", None),
            )
            exc.diagnostics = diagnostics
            raise exc from error
        return cls(native, diagnostics)

    @property
    def edition(self) -> Edition:
        return self._edition

    @property
    def diagnostics(self) -> tuple[SclDiagnostic, ...]:
        """Problems reported by :meth:`from_scl` (empty for a built model)."""
        return self._diagnostics

    @property
    def logical_devices(self) -> tuple[ModelNode, ...]:
        return tuple(ModelNode(self, i) for i in self._native.logical_devices())

    def find(self, ref: Ref) -> ModelNode | None:
        """The LD, LN, DO, control block or DA named by ``ref`` (without array index); with an FC
        only attributes with that FC are considered below the LN."""
        i = self._native.find(_text(ref))
        return ModelNode(self, i) if i is not None else None

    def type_of(self, ref: Ref) -> DataDefinition:
        """The type of the value of ``ref`` as the server sees it (FC optional for a data
        attribute; array elements by index). Raises :class:`ObjectNotFound`."""
        return DataDefinition._from(self._native.definition(_text(ref)))

    @property
    def data_sets(self) -> tuple[DataSetDefinition, ...]:
        out = []
        for ln, name, members in self._native.data_sets():
            out.append(
                DataSetDefinition(
                    self._ref(f"{ln}.{name}"),
                    tuple(self._ref(m) for m in members),
                )
            )
        return tuple(out)

    @property
    def report_controls(self) -> tuple[tuple[ObjectReference, ReportControl], ...]:
        """``(LN reference, ReportControl)`` for every RCB instance."""
        out = []
        for d in self._native.report_controls():
            rc = ReportControl(
                name=d["name"],
                buffered=d["buffered"],
                rpt_id=d["rpt_id"],
                data_set=d["data_set"],
                conf_rev=d["conf_rev"],
                opt_flds=OptFlds(d["opt_flds"] & 0x3FE),
                buf_tm=d["buf_tm"],
                trg_ops=TrgOps(d["trg_ops"] & 0x7E),
                intg_pd=d["intg_pd"],
            )
            out.append((self._ref(d["ln"]), rc))
        return tuple(out)

    @property
    def setting_group_controls(self) -> tuple[tuple[ObjectReference, SettingGroupControl], ...]:
        """``(LN reference, SettingGroupControl)`` for every SGCB."""
        return tuple(
            (self._ref(ln), SettingGroupControl(n, act, resv))
            for ln, n, act, resv in self._native.setting_group_controls()
        )

    @property
    def logs(self) -> tuple[ObjectReference, ...]:
        """The logs, as "LD/LN.LogName"."""
        return tuple(self._ref(f"{ln}.{name}") for ln, name in self._native.logs())

    @property
    def log_controls(self) -> tuple[tuple[ObjectReference, LogControl], ...]:
        out = []
        for d in self._native.log_controls():
            lc = LogControl(
                name=d["name"],
                data_set=d["data_set"],
                log_name=d["log_name"],
                log_ln=d["log_ln"],
                log_ena=d["log_ena"],
                trg_ops=TrgOps(d["trg_ops"] & 0x7E),
                intg_pd=d["intg_pd"],
            )
            out.append((self._ref(d["ln"]), lc))
        return tuple(out)

    @property
    def goose_controls(self) -> tuple[tuple[ObjectReference, GooseControl], ...]:
        return tuple((self._ref(d["ln"]), GooseControl._from(d)) for d in self._native.goose_controls())

    def _ref(self, text: str) -> ObjectReference:
        return ObjectReference(text, edition=self._edition, strict_ln_names=False)

    # The TypeSpec of a reference (cached; thread safe enough under the GIL).
    def _spec(self, text: str) -> TypeSpec:
        try:
            spec = self._specs[text]
        except KeyError:
            try:
                spec = spec_from_definition(self._native.definition(text))
            except ObjectNotFound:
                spec = None
            if len(self._specs) < 65536:
                self._specs[text] = spec
        if spec is None:
            raise ObjectNotFound(f"no such data in the model: {text}", category="openiec61850.server", code=1)
        return spec

    def _spec_or_none(self, text: str) -> TypeSpec | None:
        try:
            return self._spec(text)
        except Exception:  # noqa: BLE001 - invalid reference text from the peer
            return None

    def __repr__(self) -> str:
        lds = ", ".join(n.name for n in self.logical_devices)
        return f"Model([{lds}], edition={self._edition.name})"


# ---------------------------------------------------------------------------------------------
# Builder


def _triggers(t: TrgOps | int | None) -> tuple[bool, bool, bool] | None:
    if t is None:
        return None
    t = TrgOps(int(t) & 0x7E)
    return (TrgOps.DATA_CHANGE in t, TrgOps.QUALITY_CHANGE in t, TrgOps.DATA_UPDATE in t)


class _Handle:
    __slots__ = ("_b", "_id")

    def __init__(self, builder: ModelBuilder, node_id: int) -> None:
        self._b = builder
        self._id = node_id

    @property
    def id(self) -> int:
        return self._id


class _AttributeParent(_Handle):
    __slots__ = ()
    _under_object = False

    def _add(
        self,
        name: str,
        fc: FC | str | None,
        basic_type: BasicType | str | None,
        size: int,
        count: int,
        triggers: TrgOps | int | None,
        value: Any,
    ) -> AttributeBuilder:
        bt = BasicType(basic_type).value if basic_type is not None else None
        spec = None
        tagged = None
        if bt is not None:
            spec = spec_from_definition(_core.type_definition(bt, int(size), int(count), int(self._b.edition)))
        if value is not None:
            tagged = encode(value, spec)
        i = self._b._native.attribute(
            self._id,
            self._under_object,
            name,
            None if fc is None else FC(fc).value,
            bt,
            int(size),
            int(count),
            _triggers(triggers),
            tagged,
        )
        return AttributeBuilder(self._b, i, spec)


class DataObjectBuilder(_AttributeParent):
    """A data object (or sub-data object) being built."""

    __slots__ = ()
    _under_object = True

    def sub_object(self, name: str) -> DataObjectBuilder:
        return DataObjectBuilder(self._b, self._b._native.sub_object(self._id, name))

    def attribute(
        self,
        name: str,
        fc: FC | str,
        basic_type: BasicType | str,
        *,
        size: int = 0,
        count: int = 0,
        triggers: TrgOps | int | None = None,
        value: Any = None,
    ) -> AttributeBuilder:
        """A leaf data attribute. ``size``: maximum length of a string type, bit count of
        CodedEnum / PackedList; ``count`` > 0: an array; ``triggers``: TrgOps.DATA_CHANGE,
        QUALITY_CHANGE and/or DATA_UPDATE; ``value``: initial value (default of the type when
        omitted)."""
        return self._add(name, fc, basic_type, size, count, triggers, value)

    def structure(
        self, name: str, fc: FC | str, *, count: int = 0, triggers: TrgOps | int | None = None
    ) -> AttributeBuilder:
        """A constructed data attribute; add its sub-attributes to the returned builder."""
        return self._add(name, fc, None, 0, count, triggers, None)


class AttributeBuilder(_AttributeParent):
    """A data attribute being built; sub-attributes inherit its FC."""

    __slots__ = ("_spec",)
    _under_object = False

    def __init__(self, builder: ModelBuilder, node_id: int, spec: TypeSpec | None) -> None:
        super().__init__(builder, node_id)
        self._spec = spec

    def attribute(
        self,
        name: str,
        basic_type: BasicType | str,
        *,
        size: int = 0,
        count: int = 0,
        triggers: TrgOps | int | None = None,
        value: Any = None,
    ) -> AttributeBuilder:
        return self._add(name, None, basic_type, size, count, triggers, value)

    def structure(self, name: str, *, count: int = 0, triggers: TrgOps | int | None = None) -> AttributeBuilder:
        return self._add(name, None, None, 0, count, triggers, None)

    def value(self, v: Any) -> AttributeBuilder:
        """Sets the initial value (an array of structures needs typed values: Struct, Int32...)."""
        self._b._native.set_value(self._id, encode(v, self._spec))
        return self

    def group_value(self, sg: int, v: Any) -> AttributeBuilder:
        """FC SG attributes: the initial value in setting group ``sg`` (1-based, checked by
        :meth:`ModelBuilder.build` against NumOfSG); groups without one start with the value."""
        self._b._native.group_value(self._id, int(sg), encode(v, self._spec))
        return self


class LogicalNodeBuilder(_Handle):
    __slots__ = ()

    def data_object(self, name: str) -> DataObjectBuilder:
        return DataObjectBuilder(self._b, self._b._native.data_object(self._id, name))

    def data_set(self, name: str, members: Iterable[Ref]) -> LogicalNodeBuilder:
        """A persistent data set of this LN; members are FCD / FCDA references (checked by
        :meth:`ModelBuilder.build`)."""
        self._b._native.data_set(self._id, name, [_text(m) for m in members])
        return self

    def report_control(self, rc: ReportControl) -> LogicalNodeBuilder:
        """A report control block of this LN."""
        self._b._native.report_control(self._id, rc._native())
        return self

    def setting_group_control(
        self, sgcb: SettingGroupControl | None = None, *, num_of_sgs: int = 1, act_sg: int = 1, resv_tms: int = 0
    ) -> LogicalNodeBuilder:
        """The setting group control block "SGCB" (LLN0 only, one per LD)."""
        c = sgcb if sgcb is not None else SettingGroupControl(num_of_sgs, act_sg, resv_tms)
        self._b._native.setting_group_control(self._id, int(c.num_of_sgs), int(c.act_sg), int(c.resv_tms))
        return self

    def log(self, name: str) -> LogicalNodeBuilder:
        """A log of this LN (the MMS journal "LN$name")."""
        self._b._native.log(self._id, name)
        return self

    def log_control(self, lc: LogControl) -> LogicalNodeBuilder:
        """A log control block of this LN."""
        self._b._native.log_control(self._id, lc._native())
        return self

    def goose_control(self, gc: GooseControl) -> LogicalNodeBuilder:
        """A GOOSE control block of this LN."""
        self._b._native.goose_control(self._id, gc._native())
        return self


class LogicalDeviceBuilder(_Handle):
    __slots__ = ()

    def logical_node(self, name: str) -> LogicalNodeBuilder:
        return LogicalNodeBuilder(self._b, self._b._native.logical_node(self._id, name))


class ModelBuilder:
    """Builds a :class:`Model` (mirrors the C++ ``server::model_builder``).

    Invalid or duplicate names raise at once (:class:`InvalidModel`, :class:`ObjectExists`);
    :meth:`build` checks the values, the data set members and the control blocks' data sets.
    """

    def __init__(self, edition: Edition | int = Edition.ED2) -> None:
        self.edition = Edition(edition)
        self._native = _core.ModelBuilder(int(self.edition))

    def logical_device(self, name: str) -> LogicalDeviceBuilder:
        return LogicalDeviceBuilder(self, self._native.logical_device(name))

    def build(self) -> Model:
        """Validates and returns the model; the builder cannot be used afterwards."""
        return Model(self._native.build())


# ---------------------------------------------------------------------------------------------
# Hook types


class ControlAction(enum.IntEnum):
    SELECT = 0  # Read of SBO or Write of SBOw (SelectWithValue)
    OPERATE = 1  # Write of Oper (TimeActivatedOperate with oper_time)
    CANCEL = 2  # Write of Cancel


@dataclass(frozen=True)
class ControlResult:
    """The answer of ``on_control``."""

    class Kind(enum.IntEnum):
        ACCEPTED = 0
        REFUSED = 1
        PENDING = 2

    kind: ControlResult.Kind = Kind.ACCEPTED
    cause: AddCause | int = AddCause.UNKNOWN

    @property
    def accepted(self) -> bool:
        return self.kind != ControlResult.Kind.REFUSED

    @classmethod
    def ok(cls) -> ControlResult:
        """Accepted (for an enhanced-security Operate also complete: positive termination)."""
        return cls(cls.Kind.ACCEPTED)

    @classmethod
    def refused(cls, cause: AddCause | int = AddCause.UNKNOWN) -> ControlResult:
        """Refused with a LastApplError carrying ``cause`` (from :meth:`ControlRequest.complete`:
        a negative CommandTermination)."""
        return cls(cls.Kind.REFUSED, add_cause(int(cause)))

    @classmethod
    def pending(cls) -> ControlResult:
        """Operate only: accepted, running until :meth:`ControlRequest.complete`."""
        return cls(cls.Kind.PENDING)


@dataclass(frozen=True)
class ControlRequest:
    """A control service on a controllable data object (IEC 61850-7-2 §20)."""

    association: int
    action: ControlAction
    object: ObjectReference  # the DO, without FC
    ctl_model: CtlModel | int
    ctl_val: Any  # None for a Select by Read of SBO
    oper_time: Timestamp | None
    origin: Originator | None
    ctl_num: int
    t: Timestamp | None
    test: bool
    check: Check
    _completion: Any = field(default=None, repr=False, compare=False)

    @property
    def can_complete(self) -> bool:
        """True for an Operate (the only request that can be pending)."""
        return self._completion is not None and bool(self._completion.valid)

    def complete(self, result: ControlResult | None = None) -> bool:
        """Completes an Operate answered as pending; any thread. Returns False when it was
        already completed or abandoned (server stopped, operate timeout)."""
        if self._completion is None:
            return False
        r = result if result is not None else ControlResult.ok()
        return bool(self._completion.complete(int(r.kind), int(r.cause)))


@dataclass(frozen=True)
class AssociationRequest:
    """What a client asked for when associating (for the ``authorize`` hook)."""

    password: str | None
    calling_ap_title: str | None
    calling_ae_qualifier: int | None
    called_ap_title: str | None
    called_ae_qualifier: int | None
    remote: tuple[str, int]


@dataclass(frozen=True)
class Identity:
    """The Identify response."""

    vendor: str = "openiec61850"
    model: str = "openiec61850"
    revision: str = "0.1"


class SettingGroupAction(enum.IntEnum):
    SELECT_ACTIVE = 0  # SelectActiveSG
    SELECT_EDIT = 1  # SelectEditSG (group 0 releases the edit buffer)
    CONFIRM_EDIT = 2  # ConfirmEditSGValues


@dataclass(frozen=True)
class SettingGroupEvent:
    """A setting group service invoked by a client, before it is applied (``on_setting_group``)."""

    association: int
    logical_device: str
    action: SettingGroupAction
    group: int


@dataclass(frozen=True)
class GooseControlState:
    """The current attributes of a GoCB (:meth:`Server.goose_control`, ``on_goose_control``)."""

    reference: ObjectReference  # "LD/LN.name[GO]"
    go_ena: bool
    go_id: str
    dat_set: str  # MMS form "LD/LN$DS"; empty: none
    members: tuple[ObjectReference, ...]
    conf_rev: int
    nds_com: bool
    dst_mac: str
    vlan_priority: int
    vlan_id: int
    app_id: int
    min_time: int
    max_time: int
    fixed_offs: bool

    @staticmethod
    def _from(model: Model, d: Mapping[str, Any]) -> GooseControlState:
        return GooseControlState(
            reference=model._ref(d["reference"]),
            go_ena=d["go_ena"],
            go_id=d["go_id"],
            dat_set=d["dat_set"],
            members=tuple(model._ref(m) for m in d["members"]),
            conf_rev=d["conf_rev"],
            nds_com=d["nds_com"],
            dst_mac=_mac_text(d["dst_mac"]),
            vlan_priority=d["vlan_priority"],
            vlan_id=d["vlan_id"],
            app_id=d["app_id"],
            min_time=d["min_time"],
            max_time=d["max_time"],
            fixed_offs=d["fixed_offs"],
        )


@dataclass(frozen=True)
class FileInfo:
    """A file of a :class:`FileStore`: its path relative to the root, size and modification time."""

    name: str
    size: int
    last_modified: datetime | None = None


def _mtime(t: datetime | float | None) -> float | None:
    if t is None:
        return None
    if isinstance(t, datetime):
        if t.tzinfo is None:
            raise ValueError("modification times must be timezone-aware")
        return t.timestamp()
    return float(t)


def _file_info(t: tuple[str, int, float | None]) -> FileInfo:
    name, size, mtime = t
    return FileInfo(name, size, datetime.fromtimestamp(mtime, timezone.utc) if mtime is not None else None)


class FileStore:
    """Base class of a Python file store served by :meth:`Server.start` (``files=``).

    Paths are relative to the store root, "/"-separated, already normalised by the server (no
    "..", "." or empty segments). Errors are raised as :class:`FileNotFoundError` (file
    non-existent), :class:`PermissionError` / :class:`IsADirectoryError` (access denied),
    :class:`FileExistsError` (duplicate name), :class:`BlockingIOError` (busy) or
    :class:`ValueError` (invalid name); anything else is logged and reported as "other".

    The methods run synchronously on the server's I/O thread (see the module documentation):
    keep them quick and never wait for the event loop.
    """

    def list(self, directory: str) -> Iterable[FileInfo]:
        """The files below ``directory`` ("" for all), recursively, or the single file it names;
        sorted by name. :class:`FileNotFoundError` when nothing has that name."""
        raise NotImplementedError

    def stat(self, path: str) -> FileInfo:
        raise NotImplementedError

    def read(self, path: str, offset: int, size: int) -> bytes:
        """At most ``size`` octets at ``offset`` (b"" at the end of the file)."""
        raise NotImplementedError

    def remove(self, path: str) -> None:
        raise NotImplementedError

    def rename(self, current: str, new: str) -> None:
        """:class:`FileExistsError` when ``new`` exists."""
        raise NotImplementedError


class _NativeFileStore:
    """A store implemented natively; also usable locally (any thread)."""

    def __init__(self, native: Any) -> None:
        self._native = native

    def list(self, directory: str = "") -> list[FileInfo]:
        return [_file_info(t) for t in self._native.list(directory)]

    def stat(self, path: str) -> FileInfo:
        return _file_info(self._native.stat(path))

    def read(self, path: str, offset: int = 0, size: int = 1 << 20) -> bytes:
        return bytes(self._native.read(path, int(offset), int(size)))

    def remove(self, path: str) -> None:
        self._native.remove(path)

    def rename(self, current: str, new: str) -> None:
        self._native.rename(current, new)


class MemoryFileStore(_NativeFileStore):
    """An in-memory file store (thread-safe), e.g. for generated files or tests."""

    def __init__(self, files: Mapping[str, bytes] | None = None) -> None:
        super().__init__(_core.FileStore.memory())
        for name, content in (files or {}).items():
            self.put(name, content)

    def put(self, path: str, content: bytes, modified: datetime | float | None = None) -> None:
        """Adds or replaces a file (``FileStoreError`` with EINVAL for an invalid name)."""
        self._native.put(path, bytes(content), _mtime(modified))

    def get(self, path: str) -> bytes | None:
        b = self._native.get(path)
        return bytes(b) if b is not None else None


class DirectoryFileStore(_NativeFileStore):
    """A directory of the local filesystem. Every operation stays inside ``root`` (symbolic links
    are followed and must resolve below it); only regular files are served. Raises
    :class:`InvalidOperation` when ``root`` is not an existing directory."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        super().__init__(_core.FileStore.directory(os.fspath(root)))

    @property
    def root(self) -> str:
        return str(self._native.root)


# file_errc (server/files.hpp)
_FILE_NOT_FOUND, _FILE_ACCESS_DENIED, _FILE_EXISTS, _FILE_INVALID_NAME, _FILE_BUSY, _FILE_NO_SPACE = range(1, 7)


def _file_errc(e: BaseException) -> int:
    if isinstance(e, FileNotFoundError):
        return _FILE_NOT_FOUND
    if isinstance(e, FileExistsError):
        return _FILE_EXISTS
    if isinstance(e, (PermissionError, IsADirectoryError)):
        return _FILE_ACCESS_DENIED
    if isinstance(e, BlockingIOError):
        return _FILE_BUSY
    if isinstance(e, FileStoreError):
        return {
            errno.ENOENT: _FILE_NOT_FOUND,
            errno.EACCES: _FILE_ACCESS_DENIED,
            errno.EEXIST: _FILE_EXISTS,
            errno.EINVAL: _FILE_INVALID_NAME,
            errno.EBUSY: _FILE_BUSY,
            errno.ENOSPC: _FILE_NO_SPACE,
        }.get(e.errno or 0, -1)
    if isinstance(e, OSError) and e.errno == errno.ENOSPC:
        return _FILE_NO_SPACE
    if isinstance(e, ValueError):
        return _FILE_INVALID_NAME
    return -1


class _FileStoreAdapter:
    """What the native server calls for a Python :class:`FileStore`: (code, value) answers."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def _call(self, what: str, fn: Callable[[], Any]) -> tuple[int, Any]:
        try:
            return (0, fn())
        except Exception as e:  # noqa: BLE001 - mapped to an MMS file error
            code = _file_errc(e)
            if code < 0:
                _log.exception("file store %s failed", what)
            return (code, None)

    @staticmethod
    def _info(f: Any) -> tuple[str, int, float | None]:
        if isinstance(f, FileInfo):
            return (f.name, int(f.size), _mtime(f.last_modified))
        name, size, *rest = f
        return (str(name), int(size), _mtime(rest[0]) if rest else None)

    def list(self, directory: str) -> tuple[int, Any]:
        return self._call("list", lambda: [self._info(f) for f in self._store.list(directory)])

    def stat(self, path: str) -> tuple[int, Any]:
        return self._call("stat", lambda: self._info(self._store.stat(path)))

    def read(self, path: str, offset: int, size: int) -> tuple[int, Any]:
        return self._call("read", lambda: bytes(self._store.read(path, offset, size)))

    def remove(self, path: str) -> tuple[int, Any]:
        return self._call("remove", lambda: self._store.remove(path))

    def rename(self, current: str, new: str) -> tuple[int, Any]:
        return self._call("rename", lambda: self._store.rename(current, new))


def _native_files(files: Any) -> Any:
    if files is None:
        return None
    if isinstance(files, _NativeFileStore):
        return files._native
    for m in ("list", "stat", "read", "remove", "rename"):
        if not callable(getattr(files, m, None)):
            raise TypeError(f"files must be a FileStore (missing {m}())")
    return _FileStoreAdapter(files)


SettingGroupHook = Callable[[SettingGroupEvent], Any]
GooseControlHook = Callable[[GooseControlState], Any]
WriteHook = Callable[[int, ObjectReference, Any], Any]
ControlHook = Callable[[ControlRequest], Any]
AuthorizeHook = Callable[[AssociationRequest], Any]


def _now(r: Any, what: str) -> Any:
    """The value of a hook result that must be known at once (drives a coroutine to completion
    when it does not suspend)."""
    if inspect.iscoroutine(r):
        try:
            r.send(None)
        except StopIteration as stop:
            return stop.value
        r.close()
        raise RuntimeError(f"the {what} hook suspended; it must answer without awaiting")
    if inspect.isawaitable(r):
        raise RuntimeError(f"the {what} hook returned an awaitable; it must answer at once")
    return r


def _ts(t: tuple[Any, ...] | None) -> Timestamp | None:
    return Timestamp.from_raw(t[1], t[2], t[3]) if t is not None else None


def _control_tuple(r: Any) -> tuple[int, int]:
    if r is None or r is True:
        return (0, 0)
    if r is False:
        return (1, int(AddCause.UNKNOWN))
    if isinstance(r, ControlResult):
        return (int(r.kind), int(r.cause))
    if isinstance(r, AddCause):
        return (1, int(r))
    raise TypeError(f"on_control must return a ControlResult, got {type(r).__name__}")


def _make_dispatchers(
    model: Model,
    loop: asyncio.AbstractEventLoop,
    on_write: WriteHook | None,
    on_control: ControlHook | None,
    authorize: AuthorizeHook | None,
    on_setting_group: SettingGroupHook | None = None,
    on_goose_control: GooseControlHook | None = None,
) -> tuple[Any, Any, Any, Any, Any]:
    # These closures are owned by the native server: they must not reference the Server object
    # (a cycle through native code is invisible to the garbage collector).
    tasks: set[asyncio.Future[Any]] = set()

    def write(association: int, ref_text: str, tagged: tuple[Any, ...]) -> int:
        try:
            ref = model._ref(ref_text)
            value = decode(tagged, model._spec_or_none(ref_text))
            r = _now(on_write(association, ref, value), "on_write")  # type: ignore[misc]
            if r is None or r is True:
                return -1
            if r is False:
                return int(DataAccessError.OBJECT_ACCESS_DENIED)
            if isinstance(r, ServiceError) and r.data_access_error is not None:
                return int(r.data_access_error)
            return int(DataAccessError(r))
        except Exception:
            _log.exception("on_write hook failed for %s", ref_text)
            return int(DataAccessError.OBJECT_ACCESS_DENIED)

    def ctl_spec(obj: str) -> TypeSpec | None:
        for svc in ("Oper", "SBOw", "Cancel"):
            spec = model._spec_or_none(f"{obj}.{svc}.ctlVal[CO]")
            if spec is not None:
                return spec
        return None

    def finish(request: ControlRequest, fut: asyncio.Future[Any]) -> None:
        tasks.discard(fut)
        if fut.cancelled():
            request.complete(ControlResult.refused(AddCause.UNKNOWN))
            return
        exc = fut.exception()
        if exc is not None:
            _log.error("on_control hook failed for %s", request.object, exc_info=exc)
            request.complete(ControlResult.refused(AddCause.UNKNOWN))
            return
        try:
            kind, cause = _control_tuple(fut.result())
        except TypeError:
            _log.exception("on_control hook returned an invalid result for %s", request.object)
            kind, cause = 1, int(AddCause.UNKNOWN)
        if kind != int(ControlResult.Kind.PENDING):
            request.complete(ControlResult(ControlResult.Kind(kind), add_cause(cause)))

    def start_task(request: ControlRequest, aw: Awaitable[Any]) -> None:
        try:
            fut = asyncio.ensure_future(aw)
        except Exception:
            _log.exception("on_control hook returned an invalid awaitable for %s", request.object)
            request.complete(ControlResult.refused(AddCause.UNKNOWN))
            return
        tasks.add(fut)
        fut.add_done_callback(lambda f: finish(request, f))

    def control(d: dict[str, Any], completion: Any) -> tuple[int, int]:
        request: ControlRequest | None = None
        try:
            obj = d["object"]
            or_cat = d["or_cat"]
            check = Check(0)
            if d["synchro_check"]:
                check |= Check.SYNCHROCHECK
            if d["interlock_check"]:
                check |= Check.INTERLOCK_CHECK
            try:
                ctl_model: CtlModel | int = CtlModel(d["ctl_model"])
            except ValueError:
                ctl_model = d["ctl_model"]
            ctl_val = d["ctl_val"]
            action = ControlAction(d["action"])
            request = ControlRequest(
                association=d["association"],
                action=action,
                object=model._ref(obj),
                ctl_model=ctl_model,
                ctl_val=decode(ctl_val, ctl_spec(obj)) if ctl_val is not None else None,
                oper_time=_ts(d["oper_time"]),
                origin=Originator(_enum_or_int(OrCat, or_cat), bytes(d["or_ident"])) if or_cat is not None else None,
                ctl_num=d["ctl_num"],
                t=_ts(d["t"]),
                test=d["test"],
                check=check,
                _completion=completion if completion.valid else None,
            )
            r = on_control(request)  # type: ignore[misc]
            if inspect.isawaitable(r):
                if request.can_complete:
                    try:
                        loop.call_soon_threadsafe(start_task, request, r)
                    except RuntimeError:  # the loop is closed
                        if inspect.iscoroutine(r):
                            r.close()
                        return (1, int(AddCause.UNKNOWN))
                    return (int(ControlResult.Kind.PENDING), 0)
                r = _now(r, "on_control")
            return _control_tuple(r)
        except Exception:
            _log.exception("on_control hook failed for %s", d.get("object"))
            return (1, int(AddCause.UNKNOWN))

    def auth(d: dict[str, Any]) -> bool:
        try:
            req = AssociationRequest(
                password=d["password"],
                calling_ap_title=d["calling_ap_title"],
                calling_ae_qualifier=d["calling_ae_qualifier"],
                called_ap_title=d["called_ap_title"],
                called_ae_qualifier=d["called_ae_qualifier"],
                remote=tuple(d["remote"]),  # type: ignore[arg-type]
            )
            return bool(_now(authorize(req), "authorize"))  # type: ignore[misc]
        except Exception:
            _log.exception("authorize hook failed")
            return False

    def setting_group(association: int, ld: str, action: int, group: int) -> int:
        try:
            event = SettingGroupEvent(association, ld, SettingGroupAction(action), group)
            r = _now(on_setting_group(event), "on_setting_group")  # type: ignore[misc]
            if r is None or r is True:
                return -1
            if r is False:
                return int(DataAccessError.OBJECT_ACCESS_DENIED)
            if isinstance(r, ServiceError) and r.data_access_error is not None:
                return int(r.data_access_error)
            return int(DataAccessError(r))
        except Exception:
            _log.exception("on_setting_group hook failed for %s", ld)
            return int(DataAccessError.OBJECT_ACCESS_DENIED)

    def run_goose_hook(state: GooseControlState) -> None:
        try:
            r = on_goose_control(state)  # type: ignore[misc]
            if inspect.isawaitable(r):
                fut = asyncio.ensure_future(r)
                tasks.add(fut)

                def done(f: asyncio.Future[Any]) -> None:
                    tasks.discard(f)
                    if not f.cancelled() and f.exception() is not None:
                        _log.error("on_goose_control hook failed", exc_info=f.exception())

                fut.add_done_callback(done)
        except Exception:
            _log.exception("on_goose_control hook failed for %s", state.reference)

    def goose_control(association: int, d: dict[str, Any]) -> None:
        try:
            state = GooseControlState._from(model, d)
            loop.call_soon_threadsafe(run_goose_hook, state)
        except RuntimeError:  # the loop is closed
            pass
        except Exception:
            _log.exception("on_goose_control dispatch failed")

    return (
        write if on_write is not None else None,
        control if on_control is not None else None,
        auth if authorize is not None else None,
        setting_group if on_setting_group is not None else None,
        goose_control if on_goose_control is not None else None,
    )


def _enum_or_int(cls: type[enum.IntEnum], v: int) -> Any:
    try:
        return cls(v)
    except ValueError:
        return v


# ---------------------------------------------------------------------------------------------
# Server


def _quality(q: Quality | int | None) -> int | None:
    if q is None:
        return None
    return q.raw if isinstance(q, Quality) else int(q)


def _timestamp(t: Timestamp | datetime | None) -> tuple[Any, ...] | None:
    if t is None:
        return None
    if not isinstance(t, (Timestamp, datetime)):
        raise TypeError(f"timestamp must be a Timestamp or an aware datetime, got {type(t).__name__}")
    return encode(t)


class Server:
    """IEC 61850 server over MMS (asyncio); start it with :meth:`start`.

    Services: Identify, GetNameList, Read / Write, GetVariableAccessAttributes, data sets,
    BRCB / URCB reporting and the four control models. :meth:`update` / :meth:`update_many` may
    be called from any thread.
    """

    def __init__(self, native: Any, model: Model) -> None:
        """Internal; use :meth:`start`."""
        self._native = native
        self._model = model

    @classmethod
    async def start(
        cls,
        model: Model,
        host: str = "0.0.0.0",
        port: int = 102,
        *,
        on_write: WriteHook | None = None,
        on_control: ControlHook | None = None,
        password: str | None = None,
        authorize: AuthorizeHook | None = None,
        max_associations: int = 16,
        identity: Identity | None = None,
        brcb_buffer_capacity: int = 1024,
        max_data_set_members: int = 128,
        max_persistent_data_sets: int = 64,
        max_association_data_sets: int = 16,
        max_names_per_response: int = 0,
        auto_timestamp: bool = True,
        default_sbo_timeout: float = 30.0,
        operate_timeout: float = 0.0,
        check_test_mode: bool = True,
        association_timeout: float = 10.0,
        handshake_timeout: float = 10.0,
        on_setting_group: SettingGroupHook | None = None,
        log_capacity: int = 1024,
        on_goose_control: GooseControlHook | None = None,
        files: FileStore | MemoryFileStore | DirectoryFileStore | None = None,
        max_open_files: int = 8,
    ) -> Server:
        """Listens on ``host:port`` (port 0: ephemeral, see :attr:`local_endpoint`).

        Hooks (see the module documentation): ``on_write(association, ref, value)`` returns
        None to accept or a :class:`DataAccessError` to refuse a client write to SP, SV, CF, DC,
        BL, SG or SE (unset: accepted); ``on_control(request)`` returns a :class:`ControlResult`
        (or an awaitable of one for an Operate; unset: every command refused with
        not-supported); ``authorize(request)`` returns True to accept an association.
        ``password`` requires that ACSE password (checked before ``authorize``).
        ``operate_timeout`` (seconds, 0: none) refuses pending operations with time-limit-over.

        ``on_setting_group(event)`` (:class:`SettingGroupEvent`) is called before SelectActiveSG,
        SelectEditSG and ConfirmEditSGValues are applied and answers like ``on_write``.
        ``log_capacity``: entries kept per log (the oldest are dropped). ``on_goose_control(state)``
        (:class:`GooseControlState`) runs on the event loop after a client changed a GoCB.
        ``files`` serves the MMS file services (unset: they are rejected); ``max_open_files``
        bounds the files open at once per association.
        """
        if not isinstance(model, Model):
            raise TypeError("model must be an openiec61850.Model")
        loop = asyncio.get_running_loop()
        ident = identity if identity is not None else Identity()
        options = {
            "max_associations": max_associations,
            "vendor": ident.vendor,
            "model": ident.model,
            "revision": ident.revision,
            "brcb_buffer_capacity": brcb_buffer_capacity,
            "max_data_set_members": max_data_set_members,
            "max_persistent_data_sets": max_persistent_data_sets,
            "max_association_data_sets": max_association_data_sets,
            "max_names_per_response": max_names_per_response,
            "auto_timestamp": auto_timestamp,
            "default_sbo_timeout": float(default_sbo_timeout),
            "operate_timeout": float(operate_timeout),
            "check_test_mode": check_test_mode,
            "association_timeout": float(association_timeout),
            "handshake_timeout": float(handshake_timeout),
            "password": password,
            "log_capacity": int(log_capacity),
            "max_open_files": int(max_open_files),
            "files": _native_files(files),
        }
        write, control, auth, sg, gc = _make_dispatchers(
            model, loop, on_write, on_control, authorize, on_setting_group, on_goose_control
        )
        native = _core.Server.start(model._native, host, int(port), options, write, control, auth, sg, gc)
        return cls(native, model)

    async def __aenter__(self) -> Server:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.stop()
        await self.wait_stopped()

    @property
    def model(self) -> Model:
        return self._model

    def stop(self) -> None:
        """Closes the listener and aborts every association. Idempotent; any thread."""
        self._native.stop()

    async def wait_stopped(self) -> None:
        """Returns once :meth:`stop` has run and every association has ended."""
        await self._native.wait_stopped()

    @property
    def association_count(self) -> int:
        return int(self._native.association_count)

    @property
    def local_endpoint(self) -> tuple[str, int]:
        host, port = self._native.local_endpoint
        return (host, port)

    @property
    def port(self) -> int:
        return int(self._native.local_endpoint[1])

    def _item(
        self, ref: Ref, value: Any, quality: Quality | int | None, timestamp: Timestamp | datetime | None
    ) -> tuple[Any, ...]:
        text = _text(ref)
        return (text, encode(value, self._model._spec(text)), _quality(quality), _timestamp(timestamp))

    def update(
        self,
        ref: Ref,
        value: Any,
        quality: Quality | int | None = None,
        timestamp: Timestamp | datetime | None = None,
    ) -> None:
        """Changes a value (a DA, a DO with an FC, a structured DA, an array element); any
        thread, does not block. ``quality`` / ``timestamp`` set the sibling ``q`` / ``t``. The
        change triggers reports per the attributes' trigger options. Raises
        :class:`ObjectNotFound`, :class:`TypeMismatch` (also ``TypeError`` / ``ValueError`` from
        the conversion), :class:`AccessDenied` for control block attributes and
        :class:`ServerStopped`."""
        self._native.update(*self._item(ref, value, quality, timestamp))

    def update_many(
        self,
        items: Mapping[Ref, Any] | Iterable[Sequence[Any]],
    ) -> None:
        """Several changes applied in one step (the reports they trigger are generated together).
        ``items``: a mapping ``{ref: value}`` or ``(ref, value[, quality[, timestamp]])`` tuples."""
        pairs: Iterable[Sequence[Any]] = items.items() if isinstance(items, Mapping) else items
        batch = []
        for it in pairs:
            if not 2 <= len(it) <= 4:
                raise InvalidOperation("update_many items are (ref, value[, quality[, timestamp]])")
            ref, value, *rest = it
            q = rest[0] if len(rest) > 0 else None
            t = rest[1] if len(rest) > 1 else None
            batch.append(self._item(ref, value, q, t))
        self._native.update_many(batch)

    async def read(self, ref: Ref) -> Any:
        """The current value of a functionally constrained reference (or of a whole LN)."""
        text = _text(ref)
        t = await self._native.read(text)
        return decode(t, self._model._spec_or_none(text))

    def select_active_setting_group(self, ld: str, sg: int) -> None:
        """Local SelectActiveSG (e.g. from an HMI); any thread. Raises :class:`ObjectNotFound`
        when ``ld`` has no SGCB and :class:`ValueOutOfRange` unless 1 <= sg <= NumOfSG."""
        self._native.select_active_setting_group(ld, int(sg))

    async def read_setting_group(self, ref: Ref, sg: int) -> Any:
        """The value of an FC SG reference in setting group ``sg`` (1-based), as stored."""
        text = _text(ref)
        t = await self._native.read_setting_group(text, int(sg))
        return decode(t, self._model._spec_or_none(text))

    async def goose_control(self, ref: Ref) -> GooseControlState:
        """The current attributes of the GoCB "LD/LN.name[GO]" (:class:`ObjectNotFound`)."""
        return GooseControlState._from(self._model, await self._native.goose_control(_text(ref)))

    async def goose_controls(self) -> list[GooseControlState]:
        """Every GoCB of the model."""
        return [GooseControlState._from(self._model, d) for d in await self._native.goose_controls()]

    def __repr__(self) -> str:
        host, port = self.local_endpoint
        return f"Server({host}:{port}, associations={self.association_count})"
