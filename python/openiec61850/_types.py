"""IEC 61850 value types: object references, functional constraints, Quality, Timestamp...

All types are immutable and hashable unless noted. Bit numbering follows IEC 61850-8-1: bit 0
is the most significant bit of the first octet of the MMS BIT STRING, and the integer ``raw``
form of the bit sets maps bit ``i`` to ``1 << i`` (as in the native core).
"""

from __future__ import annotations

import enum
import functools
import re
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple, SupportsIndex, overload

from openiec61850 import _core
from openiec61850._errors import InvalidReference

__all__ = [
    "Edition",
    "FC",
    "PathElement",
    "LnParts",
    "ObjectReference",
    "BasicType",
    "MmsType",
    "ObjectClass",
    "BitString",
    "BooleanArray",
    "Struct",
    "Array",
    "Int8",
    "Int16",
    "Int24",
    "Int32",
    "Int64",
    "UInt8",
    "UInt16",
    "UInt24",
    "UInt32",
    "UInt64",
    "Bcd",
    "Float32",
    "Float64",
    "VisibleString",
    "UnicodeString",
    "GeneralizedTime",
    "OctetString",
    "ObjectIdentifier",
    "Validity",
    "Source",
    "Quality",
    "TimeAccuracy",
    "Timestamp",
    "EntryTime",
    "EntryID",
    "DbPos",
    "StepCommand",
    "Check",
    "OrCat",
    "CtlModel",
    "Behaviour",
    "Health",
    "TrgOps",
    "OptFlds",
]


class Edition(enum.IntEnum):
    """Edition of IEC 61850 implemented by a server (name length limits)."""

    ED1 = 1
    ED2 = 2
    ED2_1 = 3


class FC(str, enum.Enum):
    """Functional constraints (IEC 61850-7-2 §6.2). ``FC("ST")`` and ``FC.ST`` are the same."""

    ST = "ST"
    MX = "MX"
    SP = "SP"
    SV = "SV"
    CF = "CF"
    DC = "DC"
    SG = "SG"
    SE = "SE"
    SR = "SR"
    OR = "OR"
    BL = "BL"
    EX = "EX"
    CO = "CO"
    US = "US"
    MS = "MS"
    RP = "RP"
    BR = "BR"
    LG = "LG"
    GO = "GO"
    GS = "GS"
    XX = "XX"

    def __str__(self) -> str:
        return self.value

    @property
    def is_control_block(self) -> bool:
        return self in (FC.RP, FC.BR, FC.LG, FC.GO, FC.GS, FC.US, FC.MS)


class PathElement(NamedTuple):
    """One name after the LN, with its optional array index."""

    name: str
    index: int | None = None

    def __str__(self) -> str:
        return self.name if self.index is None else f"{self.name}({self.index})"


class LnParts(NamedTuple):
    """``[prefix]LNClass[inst]`` components of an LN name."""

    prefix: str
    ln_class: str
    inst: str


_CHILD = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)(?:\((\d+)\))?$")


@functools.total_ordering
class ObjectReference:
    """A validated ACSI object reference: ``LD[/LN[.Name[(index)]]...][[FC]]`` or ``@DataSet``.

    >>> r = ObjectReference("IED1LD0/MMXU1.TotW[MX]")
    >>> r.ld, r.ln, r.fc
    ('IED1LD0', 'MMXU1', <FC.MX: 'MX'>)
    >>> str(r / "mag" / "f")
    'IED1LD0/MMXU1.TotW.mag.f[MX]'

    References compare equal to their string form, so ``ref == "IED1LD0/MMXU1.TotW[MX]"``.
    ``strict_ln_names`` requires LN names of the form ``[prefix]LNClass[inst]``.
    """

    __slots__ = ("_text", "_ld", "_ln", "_path", "_fc", "_aa", "_edition", "_strict")

    _text: str
    _ld: str
    _ln: str
    _path: tuple[PathElement, ...]
    _fc: FC | None
    _aa: bool
    _edition: Edition
    _strict: bool

    def __init__(
        self,
        text: str | ObjectReference,
        fc: FC | str | None = None,
        *,
        edition: Edition | int = Edition.ED2,
        strict_ln_names: bool = True,
    ) -> None:
        if isinstance(text, ObjectReference):
            text = str(text)
        parts = _core.parse_reference(str(text), int(edition), strict_ln_names)
        self._assign(parts, Edition(edition), strict_ln_names)
        if fc is not None:
            self._fc = FC(fc)

    def _assign(self, parts: tuple[Any, ...], edition: Edition, strict: bool) -> None:
        text, ld, ln, path, fc, aa = parts
        self._text = text
        self._ld = ld
        self._ln = ln
        self._path = tuple(PathElement(n, i) for n, i in path)
        self._fc = FC(fc) if fc is not None else None
        self._aa = aa
        self._edition = edition
        self._strict = strict

    @classmethod
    def parse(
        cls, text: str, *, edition: Edition | int = Edition.ED2, strict_ln_names: bool = True
    ) -> ObjectReference:
        return cls(text, edition=edition, strict_ln_names=strict_ln_names)

    @classmethod
    def make(
        cls,
        ld: str,
        ln: str | None = None,
        path: Iterable[str | PathElement | tuple[str, int | None]] = (),
        fc: FC | str | None = None,
        *,
        edition: Edition | int = Edition.ED2,
        strict_ln_names: bool = True,
    ) -> ObjectReference:
        """Builds ``ld/ln.path...`` with the same validation as parsing."""
        elements = [_element(p) for p in path]
        if ln is None:
            if elements or fc is not None:
                raise InvalidReference("an LD-only reference has no path nor FC")
            text = ld
        else:
            text = "/".join((ld, ln))
            if elements:
                text += "." + ".".join(str(e) for e in elements)
        if fc is not None:
            text += f"[{FC(fc).value}]"
        return cls(text, edition=edition, strict_ln_names=strict_ln_names)

    @classmethod
    def association_specific(cls, name: str, *, edition: Edition | int = Edition.ED2) -> ObjectReference:
        """``@name``: a data set that exists for one association only."""
        return cls("@" + name, edition=edition)

    @classmethod
    def from_mms(
        cls, text: str, *, edition: Edition | int = Edition.ED2, strict_ln_names: bool = False
    ) -> ObjectReference:
        """Parses the MMS form ``LD/LN$FC$DO$DA`` (report data references, GoCB datSet...), where
        an element of an array of data objects reads ``LD/LN$FC$DO(1)$DA``."""
        canonical = _core.from_mms_data_reference(text, int(edition), strict_ln_names)
        return cls(canonical, edition=edition, strict_ln_names=strict_ln_names)

    @classmethod
    def from_mms_data_set(
        cls, text: str, *, edition: Edition | int = Edition.ED2, strict_ln_names: bool = False
    ) -> ObjectReference:
        """Parses a data set reference in MMS form: ``LD/LN$DS`` or ``@DS``."""
        canonical = _core.from_mms_data_set_reference(text, int(edition), strict_ln_names)
        return cls(canonical, edition=edition, strict_ln_names=strict_ln_names)

    def to_mms(self) -> str:
        """MMS form ``LD/LN$FC$DO$DA`` (needs an FC unless it names an LN or LD)."""
        return _core.to_mms_reference(str(self), int(self._edition))

    def to_mms_data_set(self) -> str:
        """Data set reference in MMS form: ``LD/LN$DS`` or ``@DS``."""
        return _core.to_mms_data_set_reference(str(self), int(self._edition))

    def to_mms_variable(self) -> tuple[int, str, str, bytes]:
        """``(scope, domain, item, alternate_access)`` of the MMS variable (IEC 61850-8-1 §8.1.3)."""
        return _core.to_mms_variable(str(self), int(self._edition))

    @property
    def text(self) -> str:
        """Canonical text without the FC suffix."""
        return self._text

    @property
    def ld(self) -> str:
        return self._ld

    @property
    def ln(self) -> str | None:
        return self._ln or None

    @property
    def has_ln(self) -> bool:
        return bool(self._ln)

    @property
    def ln_parts(self) -> LnParts | None:
        """Components of the LN name; the whole name is the class when it has no such form."""
        if not self._ln:
            return None
        parts = _core.split_ln_name(self._ln)
        return LnParts(*parts) if parts is not None else LnParts("", self._ln, "")

    @property
    def path(self) -> tuple[PathElement, ...]:
        """The names after the LN; for an association-specific reference, the data set name."""
        return self._path

    @property
    def depth(self) -> int:
        return len(self._path)

    @property
    def leaf(self) -> PathElement | None:
        return self._path[-1] if self._path else None

    @property
    def has_index(self) -> bool:
        return any(e.index is not None for e in self._path)

    @property
    def fc(self) -> FC | None:
        return self._fc

    @property
    def edition(self) -> Edition:
        return self._edition

    @property
    def is_association_specific(self) -> bool:
        return self._aa

    def with_fc(self, fc: FC | str | None) -> ObjectReference:
        r = self._copy()
        r._fc = FC(fc) if fc is not None else None
        return r

    def child(self, name: str, index: int | None = None) -> ObjectReference:
        """Appends ``.name[(index)]`` (``/name`` to an LD-only reference); keeps the FC."""
        if self._aa:
            raise InvalidReference("an association-specific reference has no children")
        sep = "." if self._ln else "/"
        text = f"{self._text}{sep}{PathElement(name, index)}"
        if self._fc is not None:
            text += f"[{self._fc.value}]"
        return ObjectReference(text, edition=self._edition, strict_ln_names=self._strict)

    def __truediv__(self, name: str) -> ObjectReference:
        m = _CHILD.match(name)
        if m is None:
            raise InvalidReference(f"invalid child name '{name}'")
        return self.child(m.group(1), int(m.group(2)) if m.group(2) is not None else None)

    @property
    def parent(self) -> ObjectReference:
        """Drops the last path element (or the LN); the FC is kept unless the result is an LD."""
        if self._aa or not self._ln:
            raise InvalidReference(f"'{self}' has no parent")
        if not self._path:
            return ObjectReference(self._ld, edition=self._edition, strict_ln_names=self._strict)
        text = f"{self._ld}/{self._ln}"
        if len(self._path) > 1:
            text += "." + ".".join(str(e) for e in self._path[:-1])
        if self._fc is not None:
            text += f"[{self._fc.value}]"
        return ObjectReference(text, edition=self._edition, strict_ln_names=self._strict)

    def is_within(self, ancestor: ObjectReference | str) -> bool:
        """True when ``ancestor`` is this reference or one of its parents (FCs are ignored)."""
        a = ancestor if isinstance(ancestor, ObjectReference) else ObjectReference(ancestor, strict_ln_names=False)
        if a._aa or self._aa:
            return a._aa == self._aa and a._text == self._text
        if a._ld != self._ld:
            return False
        if not a._ln:
            return True
        if a._ln != self._ln or len(a._path) > len(self._path):
            return False
        return self._path[: len(a._path)] == a._path

    def _copy(self) -> ObjectReference:
        r = object.__new__(ObjectReference)
        for s in ObjectReference.__slots__:
            setattr(r, s, getattr(self, s))
        return r

    def __str__(self) -> str:
        return self._text if self._fc is None else f"{self._text}[{self._fc.value}]"

    def __repr__(self) -> str:
        return f"ObjectReference({str(self)!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ObjectReference):
            return self._text == other._text and self._fc == other._fc
        if isinstance(other, str):
            return str(self) == other
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ObjectReference):
            return NotImplemented
        return self._key() < other._key()

    def _key(self) -> tuple[str, int]:
        order = -1 if self._fc is None else list(FC).index(self._fc)
        return (self._text, order)

    def __hash__(self) -> int:
        return hash(str(self))

    def __reduce__(self) -> tuple[Any, ...]:
        return (_rebuild_reference, (str(self), int(self._edition), self._strict))


def _rebuild_reference(text: str, edition: int, strict: bool) -> ObjectReference:
    return ObjectReference(text, edition=edition, strict_ln_names=strict)


def _element(p: str | PathElement | tuple[str, int | None]) -> PathElement:
    if isinstance(p, PathElement):
        return p
    if isinstance(p, tuple):
        return PathElement(*p)
    m = _CHILD.match(p)
    if m is None:
        raise InvalidReference(f"invalid path element '{p}'")
    return PathElement(m.group(1), int(m.group(2)) if m.group(2) is not None else None)


class BasicType(str, enum.Enum):
    """Basic attribute types; the values are the SCL bType names."""

    BOOLEAN = "BOOLEAN"
    INT8 = "INT8"
    INT16 = "INT16"
    INT24 = "INT24"
    INT32 = "INT32"
    INT64 = "INT64"
    INT128 = "INT128"
    INT8U = "INT8U"
    INT16U = "INT16U"
    INT24U = "INT24U"
    INT32U = "INT32U"
    FLOAT32 = "FLOAT32"
    FLOAT64 = "FLOAT64"
    ENUMERATED = "Enum"
    CODED_ENUM = "CodedEnum"
    PACKED_LIST = "PackedList"
    OCTET_STRING = "Octet"
    VISIBLE_STRING = "VisString"
    UNICODE_STRING = "Unicode"
    TIMESTAMP = "Timestamp"
    ENTRY_TIME = "EntryTime"
    QUALITY = "Quality"
    OBJECT_REFERENCE = "ObjRef"
    ENTRY_ID = "EntryID"
    DBPOS = "Dbpos"
    TCMD = "Tcmd"
    CHECK = "Check"
    TRG_OPS = "TrgOps"
    OPT_FLDS = "OptFlds"


class MmsType(enum.IntEnum):
    """MMS Data alternatives (ISO 9506-2 §14.4.2), numerically equal to their context tag."""

    ARRAY = 1
    STRUCTURE = 2
    BOOLEAN = 3
    BIT_STRING = 4
    INTEGER = 5
    UNSIGNED = 6
    FLOATING_POINT = 7
    OCTET_STRING = 9
    VISIBLE_STRING = 10
    GENERALIZED_TIME = 11
    BINARY_TIME = 12
    BCD = 13
    BOOLEAN_ARRAY = 14
    OBJ_ID = 15
    MMS_STRING = 16
    UTC_TIME = 17


class ObjectClass(enum.IntEnum):
    """MMS ObjectClass for :meth:`Client.name_list`."""

    NAMED_VARIABLE = 0
    SCATTERED_ACCESS = 1
    NAMED_VARIABLE_LIST = 2
    NAMED_TYPE = 3
    SEMAPHORE = 4
    EVENT_CONDITION = 5
    EVENT_ACTION = 6
    EVENT_ENROLLMENT = 7
    JOURNAL = 8
    DOMAIN = 9
    PROGRAM_INVOCATION = 10
    OPERATOR_STATION = 11


# ---------------------------------------------------------------------------------------------
# Bit strings and containers


class BitString:
    """An MMS BIT STRING. Bit 0 is the most significant bit of the first octet.

    ``BitString("0101")``, ``BitString([False, True])``, ``BitString.from_int(raw, n)`` (bit ``i``
    is ``1 << i``) and ``BitString.from_bytes(data, n)`` all build one.
    """

    __slots__ = ("_data", "_n")
    _mms_tag = 4

    def __init__(self, bits: str | Iterable[bool | int] = ()) -> None:
        if isinstance(bits, str):
            if any(c not in "01" for c in bits):
                raise ValueError("a bit string literal has only '0' and '1'")
            values = [c == "1" for c in bits]
        else:
            values = [bool(b) for b in bits]
        data = bytearray((len(values) + 7) // 8)
        for i, v in enumerate(values):
            if v:
                data[i // 8] |= 0x80 >> (i % 8)
        self._data = bytes(data)
        self._n = len(values)

    @classmethod
    def from_bytes(cls, data: bytes, bit_count: int | None = None) -> BitString:
        n = len(data) * 8 if bit_count is None else bit_count
        if n < 0 or (n + 7) // 8 > len(data):
            raise ValueError("bit count does not fit the data")
        b = bytearray(data[: (n + 7) // 8])
        if n % 8:
            b[-1] &= (0xFF << (8 - n % 8)) & 0xFF
        r = object.__new__(cls)
        r._data = bytes(b)
        r._n = n
        return r

    @classmethod
    def from_int(cls, value: int, bit_count: int) -> BitString:
        return cls((value >> i) & 1 for i in range(bit_count))

    def to_int(self) -> int:
        return sum(1 << i for i, b in enumerate(self) if b)

    def to_bytes(self) -> bytes:
        return self._data

    @property
    def bits(self) -> tuple[bool, ...]:
        return tuple(self)

    def __len__(self) -> int:
        return self._n

    @overload
    def __getitem__(self, i: SupportsIndex) -> bool: ...
    @overload
    def __getitem__(self, i: slice) -> BitString: ...
    def __getitem__(self, i: SupportsIndex | slice) -> bool | BitString:
        if isinstance(i, slice):
            return type(self)(self.bits[i])
        k = i.__index__()
        if k < 0:
            k += self._n
        if not 0 <= k < self._n:
            raise IndexError("bit index out of range")
        return bool(self._data[k // 8] & (0x80 >> (k % 8)))

    def __iter__(self) -> Iterator[bool]:
        for k in range(self._n):
            yield bool(self._data[k // 8] & (0x80 >> (k % 8)))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BitString):
            return type(self) is type(other) and self._n == other._n and self._data == other._data
        return NotImplemented

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._n, self._data))

    def __str__(self) -> str:
        return "".join("1" if b else "0" for b in self)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r})"


class BooleanArray(BitString):
    """MMS booleanArray (same layout as a BIT STRING)."""

    __slots__ = ()
    _mms_tag = 14


class Struct(list):  # type: ignore[type-arg]
    """An MMS structure: a list of components, optionally named (from a data definition).

    Named components are also reachable by name: ``value["mag"]``, ``value.get("q")``.
    """

    names: tuple[str, ...] | None

    def __init__(self, components: Iterable[Any] = (), names: Iterable[str] | None = None) -> None:
        if isinstance(components, Mapping):
            names = tuple(components.keys())
            components = components.values()
        super().__init__(components)
        self.names = tuple(names) if names is not None else None
        if self.names is not None and len(self.names) != len(self):
            raise ValueError("one name per component")

    def __getitem__(self, key: Any) -> Any:  # type: ignore[override]
        if isinstance(key, str):
            return super().__getitem__(self._index(key))
        return super().__getitem__(key)

    def _index(self, name: str) -> int:
        if self.names is None or name not in self.names:
            raise KeyError(name)
        return self.names.index(name)

    def get(self, name: str, default: Any = None) -> Any:
        try:
            return self[name]
        except KeyError:
            return default

    def as_dict(self) -> dict[str, Any]:
        """Components by name (positional names ``"0"``, ``"1"``... when unnamed)."""
        names = self.names if self.names is not None else [str(i) for i in range(len(self))]
        return dict(zip(names, self))

    def __repr__(self) -> str:
        if self.names is not None:
            return f"Struct({self.as_dict()!r})"
        return f"Struct({list(self)!r})"


class Array(list):  # type: ignore[type-arg]
    """An MMS array."""

    def __repr__(self) -> str:
        return f"Array({list(self)!r})"


# ---------------------------------------------------------------------------------------------
# Typed scalars for writing (subclasses of the natural Python type)


class _TypedInt(int):
    _mms_tag = 5
    _width = 64
    _signed = True

    def __new__(cls, value: SupportsIndex | str = 0) -> Any:
        v = int.__new__(cls, value)  # type: ignore[arg-type]
        lo, hi = cls.limits()
        if not lo <= v <= hi:
            raise OverflowError(f"{int(v)} does not fit {cls.__name__}")
        return v

    @classmethod
    def limits(cls) -> tuple[int, int]:
        if cls._signed:
            return -(1 << (cls._width - 1)), (1 << (cls._width - 1)) - 1
        return 0, (1 << cls._width) - 1

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)})"


class Int8(_TypedInt):
    _width = 8


class Int16(_TypedInt):
    _width = 16


class Int24(_TypedInt):
    _width = 24


class Int32(_TypedInt):
    _width = 32


class Int64(_TypedInt):
    _width = 64


class UInt8(_TypedInt):
    _mms_tag = 6
    _width = 8
    _signed = False


class UInt16(UInt8):
    _width = 16


class UInt24(UInt8):
    _width = 24


class UInt32(UInt8):
    _width = 32


class UInt64(UInt8):
    _width = 64


class Bcd(UInt8):
    """MMS bcd (non-negative integer)."""

    _mms_tag = 13
    _width = 64


class Float32(float):
    """FLOAT32 (MMS floating-point, exponent width 8)."""

    def __repr__(self) -> str:
        return f"Float32({float(self)!r})"


class Float64(float):
    """FLOAT64 (MMS floating-point, exponent width 11)."""

    def __repr__(self) -> str:
        return f"Float64({float(self)!r})"


class VisibleString(str):
    """MMS visible-string (VISIBLE STRING / ObjectReference)."""

    def __repr__(self) -> str:
        return f"VisibleString({str(self)!r})"


class UnicodeString(str):
    """MMS MMSString (UNICODE STRING, UTF-8)."""

    def __repr__(self) -> str:
        return f"UnicodeString({str(self)!r})"


class GeneralizedTime(str):
    """MMS generalized-time, as its text."""

    def __repr__(self) -> str:
        return f"GeneralizedTime({str(self)!r})"


class OctetString(bytes):
    """MMS octet-string."""

    def __repr__(self) -> str:
        return f"OctetString({bytes(self)!r})"


class ObjectIdentifier(tuple):  # type: ignore[type-arg]
    """MMS objId: a tuple of arcs; ``ObjectIdentifier("1.0.9506")`` parses dotted notation."""

    def __new__(cls, arcs: str | Iterable[int]) -> ObjectIdentifier:
        if isinstance(arcs, str):
            arcs = (int(a) for a in arcs.split("."))
        return super().__new__(cls, (int(a) for a in arcs))

    def __str__(self) -> str:
        return ".".join(str(a) for a in self)

    def __repr__(self) -> str:
        return f"ObjectIdentifier({str(self)!r})"


# ---------------------------------------------------------------------------------------------
# Quality


class Validity(enum.IntEnum):
    GOOD = 0
    INVALID = 1
    RESERVED = 2
    QUESTIONABLE = 3


class Source(enum.IntEnum):
    PROCESS = 0
    SUBSTITUTED = 1


_QUALITY_FLAGS = (
    ("overflow", "overflow"),
    ("out_of_range", "outOfRange"),
    ("bad_reference", "badReference"),
    ("oscillatory", "oscillatory"),
    ("failure", "failure"),
    ("old_data", "oldData"),
    ("inconsistent", "inconsistent"),
    ("inaccurate", "inaccurate"),
    ("substituted", "substituted"),
    ("test", "test"),
    ("operator_blocked", "operatorBlocked"),
)


class Quality:
    """Quality (IEC 61850-7-3 §6.2): a BIT STRING(13).

    >>> q = Quality(Validity.INVALID, old_data=True)
    >>> str(q), q.is_good, q.raw
    ('invalid|oldData', False, 130)
    """

    __slots__ = ("_raw",)
    BIT_COUNT = 13

    def __init__(
        self,
        validity: Validity = Validity.GOOD,
        *,
        overflow: bool = False,
        out_of_range: bool = False,
        bad_reference: bool = False,
        oscillatory: bool = False,
        failure: bool = False,
        old_data: bool = False,
        inconsistent: bool = False,
        inaccurate: bool = False,
        source: Source = Source.PROCESS,
        test: bool = False,
        operator_blocked: bool = False,
    ) -> None:
        v = int(validity)
        raw = ((v >> 1) & 1) | ((v & 1) << 1)
        flags = (
            overflow,
            out_of_range,
            bad_reference,
            oscillatory,
            failure,
            old_data,
            inconsistent,
            inaccurate,
            source == Source.SUBSTITUTED,
            test,
            operator_blocked,
        )
        for i, on in enumerate(flags):
            if on:
                raw |= 1 << (i + 2)
        self._raw = raw

    @classmethod
    def from_raw(cls, raw: int) -> Quality:
        q = object.__new__(cls)
        q._raw = raw & 0x1FFF
        return q

    @classmethod
    def from_bitstring(cls, bits: BitString) -> Quality:
        """Tolerant: missing bits read as zero, bits beyond 12 are ignored."""
        return cls.from_raw(sum(1 << i for i, b in enumerate(bits) if b and i < 13))

    def to_bitstring(self) -> BitString:
        return BitString.from_int(self._raw, self.BIT_COUNT)

    @property
    def raw(self) -> int:
        return self._raw

    @property
    def validity(self) -> Validity:
        return Validity(((self._raw & 1) << 1) | ((self._raw >> 1) & 1))

    @property
    def is_good(self) -> bool:
        return self.validity == Validity.GOOD

    def _flag(self, i: int) -> bool:
        return bool(self._raw & (1 << (i + 2)))

    overflow = property(lambda self: self._flag(0))
    out_of_range = property(lambda self: self._flag(1))
    bad_reference = property(lambda self: self._flag(2))
    oscillatory = property(lambda self: self._flag(3))
    failure = property(lambda self: self._flag(4))
    old_data = property(lambda self: self._flag(5))
    inconsistent = property(lambda self: self._flag(6))
    inaccurate = property(lambda self: self._flag(7))
    test = property(lambda self: self._flag(9))
    operator_blocked = property(lambda self: self._flag(10))

    @property
    def source(self) -> Source:
        return Source.SUBSTITUTED if self._flag(8) else Source.PROCESS

    def replace(self, **changes: Any) -> Quality:
        """A copy with some members changed (same keywords as the constructor)."""
        current: dict[str, Any] = {"validity": self.validity, "source": self.source}
        for attr, _ in _QUALITY_FLAGS:
            if attr != "substituted":
                current[attr] = getattr(self, attr)
        current.update(changes)
        return Quality(**current)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Quality):
            return self._raw == other._raw
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("Quality", self._raw))

    def __str__(self) -> str:
        names = [self.validity.name.lower()]
        names += [label for i, (_, label) in enumerate(_QUALITY_FLAGS) if self._flag(i)]
        return "|".join(names)

    def __repr__(self) -> str:
        return f"Quality({str(self)!r})"


# ---------------------------------------------------------------------------------------------
# Time


class TimeAccuracy(enum.IntEnum):
    """Time accuracy classes (IEC 61850-5 / 7-2), as numbers of significant fraction bits."""

    T0 = 7
    T1 = 10
    T2 = 14
    T3 = 16
    T4 = 18
    T5 = 20
    UNSPECIFIED = 31


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_LEAP_SECONDS_KNOWN = 0x80
_CLOCK_FAILURE = 0x40
_CLOCK_NOT_SYNCHRONIZED = 0x20


@functools.total_ordering
class Timestamp:
    """TimeStamp (IEC 61850-8-1 §8.1.3.7): a UTC instant with a 2^-24 s fraction and TimeQuality.

    ``ts.datetime`` is a timezone-aware UTC :class:`datetime` (microsecond precision);
    ``seconds`` / ``fraction`` / ``time_quality`` are the exact encoded values.
    """

    __slots__ = ("_seconds", "_fraction", "_quality")

    def __init__(
        self,
        when: datetime,
        *,
        accuracy: int = TimeAccuracy.UNSPECIFIED,
        leap_seconds_known: bool = False,
        clock_failure: bool = False,
        clock_not_synchronized: bool = False,
    ) -> None:
        if when.tzinfo is None:
            raise ValueError("Timestamp needs a timezone-aware datetime")
        delta = when - _EPOCH
        ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
        self._set_ns(ns)
        self._quality = _time_quality(accuracy, leap_seconds_known, clock_failure, clock_not_synchronized)

    def _set_ns(self, ns: int) -> None:
        seconds, rest = divmod(ns, 1_000_000_000)
        if not 0 <= seconds <= 0xFFFFFFFF:
            raise ValueError("Timestamp out of range (1970 .. 2106)")
        frac = ((rest << 24) + 500_000_000) // 1_000_000_000
        self._seconds = seconds
        self._fraction = min(frac, 0xFFFFFF)

    @classmethod
    def from_raw(cls, seconds: int, fraction: int, quality: int = 0) -> Timestamp:
        t = object.__new__(cls)
        t._seconds = seconds & 0xFFFFFFFF
        t._fraction = fraction & 0xFFFFFF
        t._quality = quality & 0xFF
        return t

    @classmethod
    def from_nanoseconds(cls, ns: int, *, accuracy: int = TimeAccuracy.UNSPECIFIED) -> Timestamp:
        t = object.__new__(cls)
        t._set_ns(ns)
        t._quality = _time_quality(accuracy, False, False, False)
        return t

    @classmethod
    def now(cls, *, accuracy: int = TimeAccuracy.UNSPECIFIED) -> Timestamp:
        return cls(datetime.now(timezone.utc), accuracy=accuracy)

    @property
    def seconds(self) -> int:
        return self._seconds

    @property
    def fraction(self) -> int:
        """FractionOfSecond in units of 2^-24 s."""
        return self._fraction

    @property
    def time_quality(self) -> int:
        return self._quality

    @property
    def nanoseconds(self) -> int:
        """Nanoseconds since the epoch (fraction rounded to the nearest nanosecond)."""
        return self._seconds * 1_000_000_000 + ((self._fraction * 1_000_000_000 + (1 << 23)) >> 24)

    @property
    def datetime(self) -> datetime:
        us = (self._fraction * 1_000_000 + (1 << 23)) >> 24
        return _EPOCH + timedelta(seconds=self._seconds, microseconds=us)

    def timestamp(self) -> float:
        """POSIX time as a float, like :meth:`datetime.timestamp`."""
        return self._seconds + self._fraction / (1 << 24)

    @property
    def leap_seconds_known(self) -> bool:
        return bool(self._quality & _LEAP_SECONDS_KNOWN)

    @property
    def clock_failure(self) -> bool:
        return bool(self._quality & _CLOCK_FAILURE)

    @property
    def clock_not_synchronized(self) -> bool:
        return bool(self._quality & _CLOCK_NOT_SYNCHRONIZED)

    @property
    def accuracy(self) -> int:
        """TimeAccuracy: significant fraction bits (0..24, 31 unspecified)."""
        return self._quality & 0x1F

    @property
    def accuracy_seconds(self) -> float | None:
        """2^-accuracy seconds; None when unspecified or invalid."""
        a = self.accuracy
        return None if a > 24 else 2.0**-a

    def replace(
        self,
        *,
        accuracy: int | None = None,
        leap_seconds_known: bool | None = None,
        clock_failure: bool | None = None,
        clock_not_synchronized: bool | None = None,
    ) -> Timestamp:
        q = _time_quality(
            self.accuracy if accuracy is None else accuracy,
            self.leap_seconds_known if leap_seconds_known is None else leap_seconds_known,
            self.clock_failure if clock_failure is None else clock_failure,
            self.clock_not_synchronized if clock_not_synchronized is None else clock_not_synchronized,
        )
        return Timestamp.from_raw(self._seconds, self._fraction, q)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Timestamp):
            return (self._seconds, self._fraction, self._quality) == (
                other._seconds,
                other._fraction,
                other._quality,
            )
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Timestamp):
            return (self._seconds, self._fraction) < (other._seconds, other._fraction)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._seconds, self._fraction, self._quality))

    def __repr__(self) -> str:
        flags = [n for n in ("leap_seconds_known", "clock_failure", "clock_not_synchronized") if getattr(self, n)]
        extra = "".join(f", {f}=True" for f in flags)
        return f"Timestamp({self.datetime.isoformat()!r}, accuracy={self.accuracy}{extra})"


def _time_quality(accuracy: int, leap: bool, failure: bool, unsync: bool) -> int:
    q = int(accuracy) & 0x1F
    if leap:
        q |= _LEAP_SECONDS_KNOWN
    if failure:
        q |= _CLOCK_FAILURE
    if unsync:
        q |= _CLOCK_NOT_SYNCHRONIZED
    return q


_ENTRY_EPOCH = datetime(1984, 1, 1, tzinfo=timezone.utc)


@functools.total_ordering
class EntryTime:
    """EntryTime / MMS TimeOfDay: milliseconds of the day and days since 1984-01-01 (or None)."""

    __slots__ = ("ms_of_day", "days")

    ms_of_day: int
    days: int | None

    def __init__(self, ms_of_day: int, days: int | None = None) -> None:
        object.__setattr__(self, "ms_of_day", ms_of_day)
        object.__setattr__(self, "days", days)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("EntryTime is immutable")

    @classmethod
    def from_datetime(cls, when: datetime) -> EntryTime:
        if when.tzinfo is None:
            raise ValueError("EntryTime needs a timezone-aware datetime")
        delta = when - _ENTRY_EPOCH
        if not 0 <= delta.days <= 0xFFFF:
            raise ValueError("EntryTime out of range (1984 .. 2163)")
        return cls((delta.seconds * 1000) + delta.microseconds // 1000, delta.days)

    @property
    def datetime(self) -> datetime | None:
        """The instant in UTC; None for the 4-octet form without a date."""
        if self.days is None:
            return None
        return _ENTRY_EPOCH + timedelta(days=self.days, milliseconds=self.ms_of_day)

    def _key(self) -> tuple[int, int]:
        return (self.days if self.days is not None else -1, self.ms_of_day)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EntryTime):
            return (self.ms_of_day, self.days) == (other.ms_of_day, other.days)
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, EntryTime):
            return self._key() < other._key()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.ms_of_day, self.days))

    def __repr__(self) -> str:
        dt = self.datetime
        if dt is not None:
            return f"EntryTime({dt.isoformat()!r})"
        return f"EntryTime(ms_of_day={self.ms_of_day})"


class EntryID:
    """EntryID of a BRCB buffer entry: 8 opaque octets (all-zero means "no entry")."""

    __slots__ = ("_b",)
    SIZE = 8

    def __init__(self, data: bytes | str = bytes(8)) -> None:
        if isinstance(data, str):
            try:
                data = bytes.fromhex(data)
            except ValueError as e:
                raise ValueError("an EntryID is 16 hexadecimal digits") from e
        data = bytes(data)
        if len(data) != self.SIZE:
            raise ValueError("an EntryID has exactly 8 octets")
        self._b = data

    @classmethod
    def from_hex(cls, text: str) -> EntryID:
        return cls(text)

    @property
    def is_zero(self) -> bool:
        return not any(self._b)

    def hex(self) -> str:
        return self._b.hex().upper()

    def __bytes__(self) -> bytes:
        return self._b

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EntryID):
            return self._b == other._b
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("EntryID", self._b))

    def __str__(self) -> str:
        return self.hex()

    def __repr__(self) -> str:
        return f"EntryID({self.hex()!r})"


# ---------------------------------------------------------------------------------------------
# Enumerations (IEC 61850-7-3 / 7-4)


class _CodedEnum(enum.IntEnum):
    """CODED ENUM in a BIT STRING(2), read MSB first (bit 0 is the high bit of the value)."""

    def to_bitstring(self) -> BitString:
        v = int(self)
        return BitString([bool(v & 2), bool(v & 1)])

    @classmethod
    def from_bitstring(cls, bits: BitString) -> Any:
        b = list(bits) + [False, False]
        return cls((2 if b[0] else 0) | (1 if b[1] else 0))


class DbPos(_CodedEnum):
    """Dbpos (DPC/DPS stVal)."""

    INTERMEDIATE = 0
    OFF = 1
    ON = 2
    BAD = 3


class StepCommand(_CodedEnum):
    """Tcmd / StepControl (BSC/ISC ctlVal)."""

    STOP = 0
    LOWER = 1
    HIGHER = 2
    RESERVED = 3


class Check(enum.IntFlag):
    """Check (control services): PACKED LIST BIT STRING(2)."""

    SYNCHROCHECK = 1
    INTERLOCK_CHECK = 2

    def to_bitstring(self) -> BitString:
        return BitString.from_int(int(self), 2)

    @classmethod
    def from_bitstring(cls, bits: BitString) -> Check:
        return cls(bits.to_int() & 3)


class OrCat(enum.IntEnum):
    NOT_SUPPORTED = 0
    BAY_CONTROL = 1
    STATION_CONTROL = 2
    REMOTE_CONTROL = 3
    AUTOMATIC_BAY = 4
    AUTOMATIC_STATION = 5
    AUTOMATIC_REMOTE = 6
    MAINTENANCE = 7
    PROCESS = 8


class CtlModel(enum.IntEnum):
    STATUS_ONLY = 0
    DIRECT_WITH_NORMAL_SECURITY = 1
    SBO_WITH_NORMAL_SECURITY = 2
    DIRECT_WITH_ENHANCED_SECURITY = 3
    SBO_WITH_ENHANCED_SECURITY = 4


class Behaviour(enum.IntEnum):
    """Mod / Beh stVal."""

    ON = 1
    ON_BLOCKED = 2
    TEST = 3
    TEST_BLOCKED = 4
    OFF = 5


class Health(enum.IntEnum):
    OK = 1
    WARNING = 2
    ALARM = 3


class TrgOps(enum.IntFlag):
    """TrgOps / TrgCond BIT STRING(6) and ReasonCode (7 bits in Ed.2)."""

    DATA_CHANGE = 1 << 1
    QUALITY_CHANGE = 1 << 2
    DATA_UPDATE = 1 << 3
    INTEGRITY = 1 << 4
    GENERAL_INTERROGATION = 1 << 5
    APPLICATION_TRIGGER = 1 << 6

    def to_bitstring(self, bit_count: int = 6) -> BitString:
        return BitString.from_int(int(self) & ((1 << bit_count) - 1) & 0x7E, bit_count)

    @classmethod
    def from_bitstring(cls, bits: BitString) -> TrgOps:
        return cls(bits.to_int() & 0x7E)


class OptFlds(enum.IntFlag):
    """OptFlds BIT STRING(10)."""

    SEQUENCE_NUMBER = 1 << 1
    REPORT_TIME_STAMP = 1 << 2
    REASON_FOR_INCLUSION = 1 << 3
    DATA_SET_NAME = 1 << 4
    DATA_REFERENCE = 1 << 5
    BUFFER_OVERFLOW = 1 << 6
    ENTRY_ID = 1 << 7
    CONF_REVISION = 1 << 8
    SEGMENTATION = 1 << 9

    def to_bitstring(self, bit_count: int = 10) -> BitString:
        return BitString.from_int(int(self) & 0x3FE, bit_count)

    @classmethod
    def from_bitstring(cls, bits: BitString) -> OptFlds:
        return cls(bits.to_int() & 0x3FE)
