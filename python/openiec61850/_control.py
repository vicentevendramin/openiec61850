"""Control services (IEC 61850-7-2 §20, mapped per IEC 61850-8-1 §20).

``ctl = await client.control("IED1LD1/XCBR1.Pos")`` reads the object's ctlModel, sboTimeout and
CO structure and returns a :class:`Control`; :meth:`Client.operate` is the one-shot form.
Refusals raise :class:`~openiec61850.ControlError` subclasses (see ``_errors.py``).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from openiec61850._types import CtlModel, ObjectReference, OrCat, Timestamp
from openiec61850._values import TypeSpec, encode, spec_from_definition

__all__ = [
    "AddCause",
    "ControlErrorCode",
    "Originator",
    "LastApplError",
    "Control",
]


class AddCause(enum.IntEnum):
    """AddCause of a LastApplError (IEC 61850-7-2 Ed.2). Values not listed are kept as ``int``."""

    UNKNOWN = 0
    NOT_SUPPORTED = 1
    BLOCKED_BY_SWITCHING_HIERARCHY = 2
    SELECT_FAILED = 3
    INVALID_POSITION = 4
    POSITION_REACHED = 5
    PARAMETER_CHANGE_IN_EXECUTION = 6
    STEP_LIMIT = 7
    BLOCKED_BY_MODE = 8
    BLOCKED_BY_PROCESS = 9
    BLOCKED_BY_INTERLOCKING = 10
    BLOCKED_BY_SYNCHROCHECK = 11
    COMMAND_ALREADY_IN_EXECUTION = 12
    BLOCKED_BY_HEALTH = 13
    ONE_OF_N_CONTROL = 14
    ABORTION_BY_CANCEL = 15
    TIME_LIMIT_OVER = 16
    ABORTION_BY_TRIP = 17
    OBJECT_NOT_SELECTED = 18
    OBJECT_ALREADY_SELECTED = 19
    NO_ACCESS_AUTHORITY = 20
    ENDED_WITH_OVERSHOOT = 21
    ABORTION_DUE_TO_DEVIATION = 22
    ABORTION_BY_COMMUNICATION_LOSS = 23
    BLOCKED_BY_COMMAND = 24
    NONE = 25
    INCONSISTENT_PARAMETERS = 26
    LOCKED_BY_OTHER_CLIENT = 27


class ControlErrorCode(enum.IntEnum):
    """LastApplError.Error (IEC 61850-8-1 §20.7)."""

    NO_ERROR = 0
    UNKNOWN = 1
    TIMEOUT_TEST_NOT_OK = 2
    OPERATOR_TEST_NOT_OK = 3


def _enum(cls: type[enum.IntEnum], v: int) -> Any:
    try:
        return cls(v)
    except ValueError:
        return v


def add_cause(v: int) -> AddCause | int:
    return _enum(AddCause, v)


@dataclass(frozen=True)
class Originator:
    """Who issues a command: orCat and orIdent (at most 64 octets)."""

    category: OrCat | int = OrCat.REMOTE_CONTROL
    identifier: bytes = b""


@dataclass(frozen=True)
class LastApplError:
    """A LastApplError InformationReport (a refused request or a negative termination)."""

    control_object: str  # CntrlObj as sent, e.g. "IED1LD1/XCBR1$CO$Pos$Oper"
    error: ControlErrorCode | int
    origin: Originator
    ctl_num: int
    add_cause: AddCause | int

    @classmethod
    def _from(cls, t: tuple[Any, ...] | None) -> LastApplError | None:
        if t is None:
            return None
        obj, err, (cat, ident), num, cause = t
        return cls(obj, _enum(ControlErrorCode, err), Originator(_enum(OrCat, cat), bytes(ident)), num,
                   add_cause(cause))


def _options(
    *,
    test: bool = False,
    interlock_check: bool = False,
    synchro_check: bool = False,
    origin: Originator | None = None,
    oper_time: Timestamp | datetime | None = None,
    ctl_num: int | None = None,
    termination_timeout: float = 10.0,
) -> dict[str, Any]:
    o = origin if origin is not None else Originator()
    return {
        "origin": (int(o.category), bytes(o.identifier)),
        "test": bool(test),
        "interlock_check": bool(interlock_check),
        "synchro_check": bool(synchro_check),
        "oper_time": encode(oper_time) if oper_time is not None else None,
        "ctl_num": ctl_num,
        "termination_timeout": float(termination_timeout),
    }


class Control:
    """A controllable data object; obtained from :meth:`Client.control`.

    Sequences and ctlNum follow the native handle: :meth:`select` / :meth:`select_with_value`
    (and :meth:`operate` / :meth:`cancel` outside a selection) start a sequence with the next
    ctlNum; :meth:`operate` / :meth:`cancel` after a selection reuse it. Only one service per
    object may be in progress at a time. Every service takes the keyword options ``test``,
    ``interlock_check``, ``synchro_check``, ``origin`` (:class:`Originator`), ``oper_time``
    (:class:`Timestamp` or aware ``datetime``; time-activated operate), ``ctl_num`` and
    ``termination_timeout`` (seconds; enhanced security).
    """

    def __init__(self, native: Any, edition: Any) -> None:
        """Internal; use :meth:`Client.control`."""
        self._native = native
        self._reference = ObjectReference(native.reference, edition=edition, strict_ln_names=False)
        t = native.ctl_val_type
        self._spec: TypeSpec | None = spec_from_definition(t) if t is not None else None

    def __repr__(self) -> str:
        return f"Control({str(self._reference)!r}, {self.ctl_model.name})"

    @property
    def reference(self) -> ObjectReference:
        """The data object, without FC."""
        return self._reference

    @property
    def ctl_model(self) -> CtlModel:
        return CtlModel(self._native.ctl_model)

    @property
    def sbo_timeout(self) -> float | None:
        """CF.sboTimeout in seconds, when read and present."""
        return self._native.sbo_timeout

    @property
    def ctl_num(self) -> int:
        """ctlNum of the current (or last) sequence."""
        return int(self._native.ctl_num)

    @property
    def selected(self) -> bool:
        """True between a successful selection and the end of the sequence (client's view)."""
        return bool(self._native.selected)

    @property
    def has_oper_time(self) -> bool | None:
        """Whether Oper has operTm (time-activated control); ``None`` when unknown."""
        return self._native.has_oper_time

    @property
    def last_error(self) -> LastApplError | None:
        """The last LastApplError received for this object."""
        return LastApplError._from(self._native.last_error)

    def _value(self, value: Any) -> tuple[Any, ...]:
        return encode(value, self._spec)

    async def select(self, **options: Any) -> None:
        """Select (sbo-with-normal-security): Read of SBO."""
        await self._native.select(_options(**options))

    async def select_with_value(self, value: Any, **options: Any) -> None:
        """SelectWithValue (sbo-with-enhanced-security): Write of SBOw."""
        await self._native.select_with_value(self._value(value), _options(**options))

    async def operate(
        self,
        value: Any,
        *,
        test: bool = False,
        interlock_check: bool = False,
        synchro_check: bool = False,
        origin: Originator | None = None,
        oper_time: Timestamp | datetime | None = None,
        ctl_num: int | None = None,
        termination_timeout: float = 10.0,
    ) -> None:
        """Operate / TimeActivatedOperate: Write of Oper. With enhanced security it returns once
        the CommandTermination arrives (:class:`~openiec61850.TerminationTimeout` otherwise)."""
        opts = _options(
            test=test,
            interlock_check=interlock_check,
            synchro_check=synchro_check,
            origin=origin,
            oper_time=oper_time,
            ctl_num=ctl_num,
            termination_timeout=termination_timeout,
        )
        await self._native.operate(self._value(value), opts)

    async def cancel(self, **options: Any) -> None:
        """Cancel: Write of Cancel with the ctlVal of the current sequence."""
        await self._native.cancel(_options(**options))
