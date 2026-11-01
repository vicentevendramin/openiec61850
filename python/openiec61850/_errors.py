"""Exception hierarchy and the mapping from native error codes.

Every failure reported by the native core is a ``std::error_code`` (a category name plus a
value). :func:`_make_error` turns it into an instance of the classes below; the native module
calls it through the factory installed by ``openiec61850/__init__.py``.

Hierarchy::

    Iec61850Error
    ├── CommunicationError (ConnectionError)
    │   ├── ConnectionRefused (ConnectionRefusedError)
    │   ├── HostNotFound
    │   ├── ConnectionLost
    │   │   ├── PeerAborted
    │   │   └── OutputLimitExceeded    the peer stopped reading and the output limit was reached
    │   ├── ConnectionClosed           released or aborted locally
    │   ├── NotConnected               no association (closed, or recovery in progress)
    │   ├── RecoveryFailed
    │   ├── TlsError                   handshake or certificate failure
    │   └── AssociationRejected
    │       ├── AuthenticationFailed
    │       └── InitiateError
    ├── Timeout (TimeoutError)
    ├── OperationAborted
    ├── ServerOverloaded               too many updates pending: nothing applied, try again later
    ├── ServiceError                   the server refused the service
    │   ├── ObjectNotFound, AccessDenied, ObjectExists, TemporarilyUnavailable,
    │   │   TypeInconsistent, ValueInvalid, ObjectInvalidated, HardwareFault,
    │   │   InvalidAddress, TypeUnsupported, ObjectAttributeInconsistent,
    │   │   AccessUnsupported, NotDeleted
    │   ├── RequestRejected, ConcludeRefused
    │   ├── FileError                  an MMS file service failed (``file_error``)
    │   └── ControlRefused, SelectFailed (also ControlError)
    ├── ControlError                   a control service failed
    │   ├── ControlRefused             LastApplError (refusal or negative CommandTermination)
    │   ├── SelectFailed               SBO read returned "" without a LastApplError
    │   ├── TerminationTimeout (Timeout)
    │   └── ControlModelMismatch (InvalidOperation)
    ├── ProtocolError                  the server violated the protocol or sent bad encodings
    ├── NotSupported (NotImplementedError)
    ├── TypeMismatch (TypeError)
    ├── ValueOutOfRange (ValueError)
    ├── InvalidOperation (ValueError)  local misuse (e.g. reading a reference without an FC)
    │   └── ServerStopped              server API used after Server.stop()
    ├── InvalidReference (ValueError)  malformed object reference
    ├── InvalidModel (ValueError)      inconsistent server data model
    ├── SclError (ValueError)          an SCL file could not be loaded (see ``diagnostics``)
    └── FileStoreError (OSError)       a local file store operation failed (``errno`` set)
"""

from __future__ import annotations

import asyncio
import enum
import errno as _errno
from collections.abc import Awaitable
from typing import Any, TypeVar

__all__ = [
    "Iec61850Error",
    "CommunicationError",
    "TlsError",
    "ConnectionRefused",
    "HostNotFound",
    "ConnectionLost",
    "PeerAborted",
    "OutputLimitExceeded",
    "ConnectionClosed",
    "NotConnected",
    "RecoveryFailed",
    "AssociationRejected",
    "AuthenticationFailed",
    "InitiateError",
    "Timeout",
    "OperationAborted",
    "ServerOverloaded",
    "ServiceError",
    "ObjectNotFound",
    "AccessDenied",
    "ObjectExists",
    "TemporarilyUnavailable",
    "TypeInconsistent",
    "ValueInvalid",
    "ObjectInvalidated",
    "HardwareFault",
    "InvalidAddress",
    "TypeUnsupported",
    "ObjectAttributeInconsistent",
    "AccessUnsupported",
    "NotDeleted",
    "RequestRejected",
    "ConcludeRefused",
    "FileError",
    "FileErrorCode",
    "FileStoreError",
    "ControlError",
    "ControlRefused",
    "SelectFailed",
    "TerminationTimeout",
    "ControlModelMismatch",
    "ErrorClass",
    "RejectType",
    "ProtocolError",
    "NotSupported",
    "TypeMismatch",
    "ValueOutOfRange",
    "InvalidOperation",
    "InvalidReference",
    "InvalidModel",
    "ServerStopped",
    "SclError",
]


class Iec61850Error(Exception):
    """Base class of every error raised by openiec61850.

    ``category`` and ``code`` identify the native error (``std::error_code``) when there is one.
    """

    category: str | None
    code: int | None

    def __init__(self, message: str = "", *, category: str | None = None, code: int | None = None):
        super().__init__(message)
        self.category = category
        self.code = code

    @property
    def message(self) -> str:
        return str(self.args[0]) if self.args else ""

    def __str__(self) -> str:
        return self.message


class CommunicationError(Iec61850Error, ConnectionError):
    """Transport or association failure."""


class ConnectionRefused(CommunicationError, ConnectionRefusedError):
    """TCP, COTP, session or presentation refusal."""


class HostNotFound(CommunicationError):
    """Name resolution failed."""


class ConnectionLost(CommunicationError):
    """The association ended without a local request (peer abort, EOF, reset...)."""


class PeerAborted(ConnectionLost):
    """A-ABORT / P-ABORT / S-ABORT from the server."""


class ConnectionClosed(CommunicationError):
    """The association was released or aborted locally."""


class NotConnected(CommunicationError):
    """No association is established (closed, or recovery in progress)."""


class TlsError(CommunicationError):
    """TLS failure: an unusable configuration, a failed handshake or a rejected certificate."""


class RecoveryFailed(CommunicationError):
    """Association recovery gave up."""


class AssociationRejected(CommunicationError):
    """The server rejected the association (AARE rejected)."""


class AuthenticationFailed(AssociationRejected):
    """The AARE was rejected with an authentication diagnostic."""


class InitiateError(AssociationRejected):
    """MMS Initiate-ErrorPDU, or no usable Initiate-ResponsePDU."""


class Timeout(Iec61850Error, TimeoutError):
    """A connect, request or release timeout expired."""


class OperationAborted(Iec61850Error):
    """The native operation was cancelled."""


class ErrorClass(enum.IntEnum):
    """MMS ServiceError errorClass (ISO 9506-2 §7.5.4)."""

    VMD_STATE = 0
    APPLICATION_REFERENCE = 1
    DEFINITION = 2
    RESOURCE = 3
    SERVICE = 4
    SERVICE_PREEMPT = 5
    TIME_RESOLUTION = 6
    ACCESS = 7
    INITIATE = 8
    CONCLUDE = 9
    CANCEL = 10
    FILE = 11
    OTHERS = 12


class RejectType(enum.IntEnum):
    """The PDU kind a RejectPDU names (rejectReason CHOICE, ISO 9506-2 §7.5.5)."""

    CONFIRMED_REQUEST = 1
    CONFIRMED_RESPONSE = 2
    CONFIRMED_ERROR = 3
    UNCONFIRMED = 4
    PDU_ERROR = 5
    CANCEL_REQUEST = 6
    CANCEL_RESPONSE = 7
    CANCEL_ERROR = 8
    CONCLUDE_REQUEST = 9
    CONCLUDE_RESPONSE = 10
    CONCLUDE_ERROR = 11


class ServiceError(Iec61850Error):
    """The server refused a service (Confirmed-ErrorPDU, RejectPDU or a DataAccessError).

    What the server sent, when it was a Confirmed-ErrorPDU: ``error_class`` (:class:`ErrorClass`),
    ``error_code``, ``additional_code``, ``additional_description`` and ``modifier_position``;
    when it was a RejectPDU: ``reject_type`` (:class:`RejectType`), ``reject_reason`` and
    ``original_invoke_id``. They are ``None`` otherwise, e.g. for the per-item DataAccessError of
    :meth:`Client.read_many`, which set ``data_access_error`` (ISO 9506-2 numbering) instead.
    """

    error_class: ErrorClass | int | None = None
    error_code: int | None = None
    additional_code: int | None = None
    additional_description: str | None = None
    modifier_position: int | None = None
    reject_type: RejectType | int | None = None
    reject_reason: int | None = None
    original_invoke_id: int | None = None
    data_access_error: int | None = None


class ObjectNotFound(ServiceError):
    data_access_error = 10  # object-non-existent (object-undefined is 4)


class AccessDenied(ServiceError):
    data_access_error = 3


class ObjectExists(ServiceError):
    pass


class ObjectInvalidated(ServiceError):
    data_access_error = 0


class HardwareFault(ServiceError):
    data_access_error = 1


class TemporarilyUnavailable(ServiceError):
    data_access_error = 2


class InvalidAddress(ServiceError):
    data_access_error = 5


class TypeUnsupported(ServiceError):
    data_access_error = 6


class TypeInconsistent(ServiceError):
    data_access_error = 7


class ObjectAttributeInconsistent(ServiceError):
    data_access_error = 8


class AccessUnsupported(ServiceError):
    data_access_error = 9


class ValueInvalid(ServiceError):
    data_access_error = 11


class NotDeleted(ServiceError):
    """DeleteDataSet matched the data set but the server kept it."""


class RequestRejected(ServiceError):
    """RejectPDU naming the request."""


class ConcludeRefused(ServiceError):
    """Conclude-ErrorPDU: the association stays established."""


class ProtocolError(Iec61850Error):
    """Protocol violation or malformed encoding from the peer."""


class NotSupported(Iec61850Error, NotImplementedError):
    """Valid per the standard but not implemented."""


class TypeMismatch(Iec61850Error, TypeError):
    """A value has an MMS type other than the one expected."""


class ValueOutOfRange(Iec61850Error, ValueError):
    """A value does not fit the requested type."""


class InvalidOperation(Iec61850Error, ValueError):
    """Local API misuse, e.g. reading a reference that is not functionally constrained."""


class InvalidReference(Iec61850Error, ValueError):
    """Malformed object reference."""


class InvalidModel(Iec61850Error, ValueError):
    """The server data model is inconsistent (builder misuse, bad values, dangling members)."""


class ServerStopped(InvalidOperation):
    """The server has been stopped."""


class ServerOverloaded(Iec61850Error):
    """``max_pending_updates`` changes are waiting to be applied, so this one was refused and
    nothing of it applied; try again later (see :attr:`Server.pending_updates`)."""


class OutputLimitExceeded(ConnectionLost):
    """The peer stopped reading and the output queued for it exceeded ``max_output_bytes``."""


class SclError(Iec61850Error, ValueError):
    """An SCL file could not be turned into a server model.

    ``diagnostics`` lists every problem found (:class:`~openiec61850.SclDiagnostic`).
    """

    diagnostics: tuple[Any, ...] = ()


class FileErrorCode(enum.IntEnum):
    """MMS file errors (ISO 9506-2 §7.5.4, errorClass ``file``)."""

    OTHER = 0
    FILENAME_AMBIGUOUS = 1
    FILE_BUSY = 2
    FILENAME_SYNTAX_ERROR = 3
    CONTENT_TYPE_INVALID = 4
    POSITION_INVALID = 5
    FILE_ACCESS_DENIED = 6
    FILE_NON_EXISTENT = 7
    DUPLICATE_FILENAME = 8
    INSUFFICIENT_SPACE_IN_FILESTORE = 9


class FileError(ServiceError):
    """The server refused a file service; ``file_error`` (:class:`FileErrorCode`) says why."""

    @property
    def file_error(self) -> FileErrorCode | int | None:
        return _enum(FileErrorCode, self.error_code)


class FileStoreError(Iec61850Error, OSError):
    """A local file store operation failed (:class:`~openiec61850.MemoryFileStore`,
    :class:`~openiec61850.DirectoryFileStore`); ``errno`` is ENOENT, EACCES, EEXIST, EINVAL,
    EBUSY or ENOSPC."""


class ControlError(Iec61850Error):
    """A control service failed.

    ``add_cause`` (:class:`~openiec61850.AddCause`) and ``last_appl_error``
    (:class:`~openiec61850.LastApplError`) are set when the server sent a LastApplError; the
    :class:`ServiceError` attributes describe the refused request itself when known.
    """

    add_cause: Any = None
    last_appl_error: Any = None
    error_class: ErrorClass | int | None = None
    error_code: int | None = None
    additional_code: int | None = None
    additional_description: str | None = None
    modifier_position: int | None = None
    reject_type: RejectType | int | None = None
    reject_reason: int | None = None
    original_invoke_id: int | None = None


class ControlRefused(ControlError, ServiceError):
    """The server refused the command with a LastApplError, or ended it with a negative
    CommandTermination; see ``add_cause``."""


class SelectFailed(ControlError, ServiceError):
    """Select (SBO read) returned an empty reference without a LastApplError."""


class TerminationTimeout(ControlError, Timeout):
    """No CommandTermination arrived within ``termination_timeout``."""


class ControlModelMismatch(ControlError, InvalidOperation):
    """The service does not exist in the object's ctlModel."""


_CLIENT = {
    1: NotConnected,
    2: ObjectNotFound,
    3: AccessDenied,
    4: ObjectExists,
    5: ObjectInvalidated,
    6: HardwareFault,
    7: TemporarilyUnavailable,
    8: InvalidAddress,
    9: TypeUnsupported,
    10: TypeInconsistent,
    11: ObjectAttributeInconsistent,
    12: AccessUnsupported,
    13: ValueInvalid,
    14: TypeMismatch,
    15: NotDeleted,
    16: RecoveryFailed,
    17: SelectFailed,
    18: TerminationTimeout,
    19: ControlModelMismatch,
}

_ASSOCIATION = {
    1: ConnectionRefused,
    2: AssociationRejected,
    3: AuthenticationFailed,
    4: InitiateError,
    5: PeerAborted,
    6: ConnectionClosed,
    7: ConnectionClosed,
    8: Timeout,
    9: ServiceError,
    10: RequestRejected,
    11: ConcludeRefused,
}

_CORE = {
    1: ProtocolError,
    2: ProtocolError,
    3: ProtocolError,
    4: NotSupported,
    5: ProtocolError,
    6: Iec61850Error,
    7: ProtocolError,
    8: ValueOutOfRange,
    9: InvalidOperation,
    10: OutputLimitExceeded,
}

_ERRNO = {
    _errno.ECONNREFUSED: ConnectionRefused,
    _errno.ETIMEDOUT: Timeout,
    _errno.ECANCELED: OperationAborted,
    _errno.ECONNRESET: ConnectionLost,
    _errno.ECONNABORTED: ConnectionLost,
    _errno.EPIPE: ConnectionLost,
    _errno.ENOTCONN: ConnectionLost,
    _errno.ESHUTDOWN: ConnectionLost,
}

# server::errc (server/error.hpp)
_SERVER = {
    1: ObjectNotFound,
    2: ObjectExists,
    3: TypeMismatch,
    4: InvalidModel,
    5: ServerStopped,
    6: AccessDenied,
    7: ServerOverloaded,
}

# server::file_errc (server/files.hpp): not_found, access_denied, exists, invalid_name, busy,
# no_space.
_FILE_ERRNO = {
    1: _errno.ENOENT,
    2: _errno.EACCES,
    3: _errno.EEXIST,
    4: _errno.EINVAL,
    5: _errno.EBUSY,
    6: _errno.ENOSPC,
}

_BY_CATEGORY: dict[str, dict[int, type[Iec61850Error]]] = {
    "openiec61850.server": _SERVER,
    "openiec61850.client": _CLIENT,
    "openiec61850.association": _ASSOCIATION,
    "openiec61850": _CORE,
}


_T = TypeVar("_T")


async def wait_for(awaitable: Awaitable[_T], timeout: float | None) -> _T:
    """``asyncio.wait_for`` raising the builtin ``TimeoutError``: on Python 3.10
    ``asyncio.TimeoutError`` is a different class."""
    try:
        return await asyncio.wait_for(awaitable, timeout)
    except asyncio.TimeoutError as e:
        raise TimeoutError() from e


def error_class_for(category: str, value: int) -> type[Iec61850Error]:
    """The exception class for a native error code."""
    if category == "openiec61850.control":
        return ControlRefused
    if category == "openiec61850.server.file":
        return FileStoreError
    table = _BY_CATEGORY.get(category)
    if table is not None:
        return table.get(value, Iec61850Error)
    if category in ("system", "generic", "asio.system"):
        return _ERRNO.get(value, CommunicationError)
    if category == "asio.misc":
        return ConnectionLost if value == 2 else CommunicationError  # 2: eof
    if category in ("asio.netdb", "asio.addrinfo"):
        return HostNotFound
    if category in ("asio.ssl", "asio.ssl.stream"):
        return TlsError
    return Iec61850Error


def _enum(cls: type[enum.IntEnum], v: int | None) -> Any:
    if v is None:
        return None
    try:
        return cls(v)
    except ValueError:
        return v


def _make_error(category: str, value: int, message: str, details: dict[str, Any] | None = None) -> BaseException:
    if category in ("system", "generic", "asio.system") and value == _errno.ENOMEM:
        return MemoryError(message)
    cls = error_class_for(category, value)
    if cls is ServiceError and details and details.get("error_class") == ErrorClass.FILE:
        cls = FileError
    exc = cls(message, category=category, code=value)
    if isinstance(exc, OSError) and category in ("system", "generic", "asio.system"):
        exc.errno = value
    if isinstance(exc, FileStoreError):
        exc.errno = _FILE_ERRNO.get(value, _errno.EIO)
    if category == "openiec61850.control" or details:
        from openiec61850._control import LastApplError, add_cause

        if category == "openiec61850.control":
            exc.add_cause = add_cause(value - 1)  # type: ignore[attr-defined]
        if details:
            for key in ("error_code", "additional_code", "additional_description", "modifier_position",
                        "reject_reason", "original_invoke_id", "service_specific_info"):
                setattr(exc, key, details.get(key))
            exc.error_class = _enum(ErrorClass, details.get("error_class"))  # type: ignore[attr-defined]
            exc.reject_type = _enum(RejectType, details.get("reject_type"))  # type: ignore[attr-defined]
            lae = LastApplError._from(details.get("last_appl_error"))
            if lae is not None:
                exc.last_appl_error = lae  # type: ignore[attr-defined]
                if getattr(exc, "add_cause", None) is None:
                    exc.add_cause = lae.add_cause  # type: ignore[attr-defined]
    return exc
