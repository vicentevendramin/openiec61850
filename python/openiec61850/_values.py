"""Conversion between Python values and MMS Data.

The native module exchanges MMS Data as tagged tuples (see python/src/convert.hpp). This module
maps them to natural Python values and back.

Reading (MMS -> Python):

==================  ============================================================
boolean             ``bool``
integer, unsigned   ``int`` (bcd too)
floating-point      ``float``
visible-string      ``str`` (MMSString and generalized-time too)
octet-string        ``bytes`` (:class:`EntryID` when the definition says EntryID)
bit-string          :class:`BitString`; :class:`Quality` for 13 bits or when the data
                    definition says Quality; :class:`DbPos`, :class:`StepCommand`,
                    :class:`Check`, :class:`TrgOps`, :class:`OptFlds` when the data
                    definition names those types
utc-time            :class:`Timestamp`
binary-time         :class:`EntryTime`
structure, array    :class:`Struct` (named when the data definition is known), :class:`Array`
==================  ============================================================

Writing (Python -> MMS) needs the MMS type, which plain ``int``/``float``/``str`` do not carry.
The type of a value is taken from, in this order:

1. the value itself when it is typed: ``bool``, the wrappers :class:`Int8` ... :class:`UInt64`,
   :class:`Float32`, :class:`Float64`, :class:`VisibleString`, :class:`UnicodeString`,
   :class:`OctetString`, :class:`BitString`, :class:`Quality`, :class:`Timestamp`,
   :class:`EntryTime`, :class:`EntryID`, :class:`DbPos`, :class:`TrgOps`, ... and plain
   ``bytes`` (octet-string) and ``datetime`` (utc-time);
2. the data definition of the reference (or of an ancestor), cached by the client after
   :meth:`Client.data_definition` - the client fetches it automatically, once per reference,
   when a plain value cannot be typed otherwise;
3. the type of the last value read from the same reference.

Inside a :class:`Struct`/:class:`Array` (or a plain list/tuple/dict written against a structure
definition) the same rules apply per component.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, NamedTuple

from openiec61850._types import (
    Array,
    BasicType,
    BitString,
    BooleanArray,
    Behaviour,
    Check,
    CtlModel,
    DbPos,
    EntryID,
    EntryTime,
    Float32,
    Float64,
    GeneralizedTime,
    Health,
    ObjectIdentifier,
    OctetString,
    OptFlds,
    OrCat,
    Quality,
    StepCommand,
    Struct,
    Timestamp,
    TrgOps,
    UnicodeString,
    VisibleString,
    _TypedInt,
)

ARRAY = 1
STRUCTURE = 2
BOOLEAN = 3
BIT_STRING = 4
INTEGER = 5
UNSIGNED = 6
FLOAT = 7
OCTET_STRING = 9
VISIBLE_STRING = 10
GENERALIZED_TIME = 11
BINARY_TIME = 12
BCD = 13
BOOLEAN_ARRAY = 14
OBJ_ID = 15
MMS_STRING = 16
UTC_TIME = 17


class TypeNeeded(TypeError):
    """A plain Python value whose MMS type cannot be inferred."""


class TypeSpec(NamedTuple):
    """The MMS type of a value, as far as conversions need it."""

    tag: int
    size: int = 0  # bit-string bits, integer width
    double: bool = False
    children: tuple[TypeSpec, ...] = ()  # structure components, or the array element
    names: tuple[str, ...] | None = None
    basic: str | None = None  # SCL bType name

    def child(self, name: str) -> TypeSpec | None:
        if self.tag == STRUCTURE and self.names is not None and name in self.names:
            return self.children[self.names.index(name)]
        return None

    def element(self) -> TypeSpec | None:
        return self.children[0] if self.tag == ARRAY and self.children else None


def spec_from_definition(d: Mapping[str, Any]) -> TypeSpec:
    """From the native data definition dict."""
    tag = int(d["mms_type"])
    children = tuple(spec_from_definition(c) for c in d["children"])
    names = tuple(c["name"] for c in d["children"]) if tag == STRUCTURE else None
    basic = d["basic_type"]
    return TypeSpec(tag, int(d["size"]), basic == BasicType.FLOAT64.value, children, names, basic)


def spec_from_tagged(t: tuple[Any, ...]) -> TypeSpec:
    """From a tagged value (the type of a value read)."""
    tag = t[0]
    if tag == STRUCTURE:
        return TypeSpec(tag, children=tuple(spec_from_tagged(c) for c in t[1]))
    if tag == ARRAY:
        return TypeSpec(tag, children=(spec_from_tagged(t[1][0]),) if t[1] else ())
    if tag in (BIT_STRING, BOOLEAN_ARRAY):
        return TypeSpec(tag, t[2])
    if tag == FLOAT:
        return TypeSpec(tag, double=bool(t[2]))
    return TypeSpec(tag)


# ---------------------------------------------------------------------------------------------
# MMS -> Python

_BITSTRING_TYPES: dict[str, Any] = {
    BasicType.QUALITY.value: Quality.from_bitstring,
    BasicType.DBPOS.value: DbPos.from_bitstring,
    BasicType.TCMD.value: StepCommand.from_bitstring,
    BasicType.CHECK.value: Check.from_bitstring,
    BasicType.TRG_OPS.value: TrgOps.from_bitstring,
    BasicType.OPT_FLDS.value: OptFlds.from_bitstring,
}


def decode(t: tuple[Any, ...], spec: TypeSpec | None = None) -> Any:
    tag = t[0]
    if tag == STRUCTURE:
        children = spec.children if spec is not None and spec.tag == STRUCTURE else ()
        values = [decode(c, children[i] if i < len(children) else None) for i, c in enumerate(t[1])]
        names = spec.names if spec is not None and spec.names is not None and len(spec.names) == len(values) else None
        return Struct(values, names)
    if tag == ARRAY:
        element = spec.element() if spec is not None else None
        return Array(decode(c, element) for c in t[1])
    if tag in (BOOLEAN, INTEGER, UNSIGNED, BCD, FLOAT, VISIBLE_STRING, MMS_STRING):
        return t[1]
    if tag == BIT_STRING:
        bits = BitString.from_bytes(t[1], t[2])
        if spec is not None and spec.basic in _BITSTRING_TYPES:
            return _BITSTRING_TYPES[spec.basic](bits)
        if (spec is None or spec.basic is None) and t[2] == Quality.BIT_COUNT:
            return Quality.from_bitstring(bits)
        return bits
    if tag == OCTET_STRING:
        if spec is not None and spec.basic == BasicType.ENTRY_ID.value and len(t[1]) == EntryID.SIZE:
            return EntryID(t[1])
        return t[1]
    if tag == UTC_TIME:
        return Timestamp.from_raw(t[1], t[2], t[3])
    if tag == BINARY_TIME:
        return EntryTime(t[1], t[2])
    if tag == GENERALIZED_TIME:
        return GeneralizedTime(t[1])
    if tag == BOOLEAN_ARRAY:
        return BooleanArray.from_bytes(t[1], t[2])
    if tag == OBJ_ID:
        return ObjectIdentifier(t[1])
    return None


# ---------------------------------------------------------------------------------------------
# Python -> MMS

_ENUMERATED = (OrCat, CtlModel, Behaviour, Health)


def _bits(tag: int, b: BitString) -> tuple[Any, ...]:
    return (tag, b.to_bytes(), len(b))


def encode(v: Any, spec: TypeSpec | None = None) -> tuple[Any, ...]:
    """The tagged form of ``v``; raises :class:`TypeNeeded` when its type cannot be inferred."""
    # Typed values first (bool and the enums are ints, so before the int checks).
    if isinstance(v, bool):
        return (BOOLEAN, v)
    if isinstance(v, Timestamp):
        return (UTC_TIME, v.seconds, v.fraction, v.time_quality)
    if isinstance(v, EntryTime):
        return (BINARY_TIME, v.ms_of_day, v.days)
    if isinstance(v, Quality):
        return _bits(BIT_STRING, v.to_bitstring())
    if isinstance(v, (DbPos, StepCommand)):
        return _bits(BIT_STRING, v.to_bitstring())
    if isinstance(v, Check):
        return _bits(BIT_STRING, v.to_bitstring())
    if isinstance(v, TrgOps):
        n = spec.size if spec is not None and spec.tag == BIT_STRING and spec.size > 0 else 6
        return _bits(BIT_STRING, v.to_bitstring(n))
    if isinstance(v, OptFlds):
        n = spec.size if spec is not None and spec.tag == BIT_STRING and spec.size > 0 else 10
        return _bits(BIT_STRING, v.to_bitstring(n))
    if isinstance(v, EntryID):
        return (OCTET_STRING, bytes(v))
    if isinstance(v, BitString):
        return _bits(v._mms_tag, v)
    if isinstance(v, _TypedInt):
        return (v._mms_tag, int(v))
    if isinstance(v, _ENUMERATED) and (spec is None or spec.tag in (INTEGER, UNSIGNED)):
        return (spec.tag if spec is not None else INTEGER, int(v))
    if isinstance(v, Float32):
        return (FLOAT, float(v), False)
    if isinstance(v, Float64):
        return (FLOAT, float(v), True)
    if isinstance(v, VisibleString):
        return (VISIBLE_STRING, str(v))
    if isinstance(v, UnicodeString):
        return (MMS_STRING, str(v))
    if isinstance(v, GeneralizedTime):
        return (GENERALIZED_TIME, str(v))
    if isinstance(v, OctetString):
        return (OCTET_STRING, bytes(v))
    if isinstance(v, ObjectIdentifier):
        return (OBJ_ID, tuple(v))
    if isinstance(v, Struct):
        children = spec.children if spec is not None and spec.tag == STRUCTURE else ()
        if children and len(children) != len(v):
            raise ValueError(f"the structure has {len(children)} components, got {len(v)}")
        return (STRUCTURE, [encode(x, children[i] if children else None) for i, x in enumerate(v)])
    if isinstance(v, Array):
        element = spec.element() if spec is not None else None
        return (ARRAY, [encode(x, element) for x in v])

    if spec is None:
        if isinstance(v, (bytes, bytearray, memoryview)):
            return (OCTET_STRING, bytes(v))
        if isinstance(v, datetime):
            return (UTC_TIME, *_raw_timestamp(Timestamp(v)))
        raise TypeNeeded(
            f"cannot infer the MMS type of a {type(v).__name__}; use a typed wrapper "
            "(Int32, Float32, VisibleString...) or let the client learn the data definition"
        )
    return _encode_as(v, spec)


def _raw_timestamp(t: Timestamp) -> tuple[int, int, int]:
    return (t.seconds, t.fraction, t.time_quality)


def _encode_as(v: Any, spec: TypeSpec) -> tuple[Any, ...]:
    tag = spec.tag
    if tag == STRUCTURE:
        if isinstance(v, Mapping):
            if spec.names is None:
                raise TypeNeeded("component names are unknown; pass the components in order")
            missing = [n for n in spec.names if n not in v]
            if missing:
                raise ValueError(f"missing structure components: {', '.join(missing)}")
            items: Sequence[Any] = [v[n] for n in spec.names]
        elif isinstance(v, (list, tuple)):
            items = v
        else:
            raise TypeError(f"a structure needs a sequence or a mapping, got {type(v).__name__}")
        if len(items) != len(spec.children):
            raise ValueError(f"the structure has {len(spec.children)} components, got {len(items)}")
        return (STRUCTURE, [encode(x, c) for x, c in zip(items, spec.children)])
    if tag == ARRAY:
        if not isinstance(v, (list, tuple)):
            raise TypeError(f"an array needs a sequence, got {type(v).__name__}")
        element = spec.element()
        return (ARRAY, [encode(x, element) for x in v])
    if tag == BOOLEAN:
        if isinstance(v, int) and v in (0, 1):
            return (BOOLEAN, bool(v))
        raise TypeError(f"expected a bool, got {type(v).__name__}")
    if tag in (BIT_STRING, BOOLEAN_ARRAY):
        if isinstance(v, int):
            bits = BitString.from_int(v, spec.size)
        elif isinstance(v, (str, list, tuple)):
            bits = BitString(v)
        else:
            raise TypeError(f"expected a BitString, got {type(v).__name__}")
        return _bits(tag, bits)
    if tag in (INTEGER, UNSIGNED, BCD):
        if isinstance(v, float) or not isinstance(v, int):
            raise TypeError(f"expected an int, got {type(v).__name__}")
        _check_int(int(v), tag, spec.size)
        return (tag, int(v))
    if tag == FLOAT:
        if not isinstance(v, (int, float)):
            raise TypeError(f"expected a float, got {type(v).__name__}")
        return (FLOAT, float(v), spec.double)
    if tag == OCTET_STRING:
        if not isinstance(v, (bytes, bytearray, memoryview)):
            raise TypeError(f"expected bytes, got {type(v).__name__}")
        return (OCTET_STRING, bytes(v))
    if tag in (VISIBLE_STRING, MMS_STRING, GENERALIZED_TIME):
        if not isinstance(v, str):
            raise TypeError(f"expected a str, got {type(v).__name__}")
        return (tag, str(v))
    if tag == UTC_TIME:
        if isinstance(v, datetime):
            return (UTC_TIME, *_raw_timestamp(Timestamp(v)))
        raise TypeError(f"expected a Timestamp or datetime, got {type(v).__name__}")
    if tag == BINARY_TIME:
        if isinstance(v, datetime):
            e = EntryTime.from_datetime(v)
            return (BINARY_TIME, e.ms_of_day, e.days)
        raise TypeError(f"expected an EntryTime or datetime, got {type(v).__name__}")
    if tag == OBJ_ID:
        return (OBJ_ID, tuple(ObjectIdentifier(v)))
    raise TypeNeeded(f"unsupported MMS type {tag}")


def _check_int(v: int, tag: int, width: int) -> None:
    if tag == INTEGER:
        bits = width if 0 < width <= 64 else 64
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    else:
        bits = width if tag == UNSIGNED and 0 < width <= 64 else 64
        lo, hi = 0, (1 << bits) - 1
    if not lo <= v <= hi:
        raise OverflowError(f"{v} does not fit the {bits}-bit {'integer' if tag == INTEGER else 'unsigned'}")
