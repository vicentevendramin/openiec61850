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
    │   │   └── PeerAborted
    │   ├── ConnectionClosed           released or aborted locally
    │   ├── NotConnected               no association (closed, or recovery in progress)
    │   ├── RecoveryFailed
    │   └── AssociationRejected
    │       ├── AuthenticationFailed
    │       └── InitiateError
    ├── Timeout (TimeoutError)
    ├── OperationAborted
    ├── ServiceError                   the server refused the service
    │   ├── ObjectNotFound, AccessDenied, ObjectExists, TemporarilyUnavailable,
    │   │   TypeInconsistent, ValueInvalid, ObjectInvalidated, HardwareFault,
    │   │   InvalidAddress, TypeUnsupported, ObjectAttributeInconsistent,
    │   │   AccessUnsupported, NotDeleted
    │   └── RequestRejected, ConcludeRefused
    ├── ProtocolError                  the server violated the protocol or sent bad encodings
    ├── NotSupported (NotImplementedError)
    ├── TypeMismatch (TypeError)
    ├── ValueOutOfRange (ValueError)
    ├── InvalidOperation (ValueError)  local misuse (e.g. reading a reference without an FC)
    └── InvalidReference (ValueError)  malformed object reference
"""

from __future__ import annotations

import errno as _errno

__all__ = [
    "Iec61850Error",
    "CommunicationError",
    "ConnectionRefused",
    "HostNotFound",
    "ConnectionLost",
    "PeerAborted",
    "ConnectionClosed",
    "NotConnected",
    "RecoveryFailed",
    "AssociationRejected",
    "AuthenticationFailed",
    "InitiateError",
    "Timeout",
    "OperationAborted",
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
    "ProtocolError",
    "NotSupported",
    "TypeMismatch",
    "ValueOutOfRange",
    "InvalidOperation",
    "InvalidReference",
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


class ServiceError(Iec61850Error):
    """The server refused a service (Confirmed-ErrorPDU or a DataAccessError).

    ``error_class`` / ``error_code`` are the MMS ServiceError class and code when known; the
    native client does not propagate them yet, so they are ``None`` except for the
    DataAccessError subclasses, which set ``data_access_error`` (ISO 9506-2 numbering).
    """

    error_class: int | None = None
    error_code: int | None = None
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

_BY_CATEGORY: dict[str, dict[int, type[Iec61850Error]]] = {
    "openiec61850.client": _CLIENT,
    "openiec61850.association": _ASSOCIATION,
    "openiec61850": _CORE,
}


def error_class_for(category: str, value: int) -> type[Iec61850Error]:
    """The exception class for a native error code."""
    table = _BY_CATEGORY.get(category)
    if table is not None:
        return table.get(value, Iec61850Error)
    if category in ("system", "generic", "asio.system"):
        return _ERRNO.get(value, CommunicationError)
    if category == "asio.misc":
        return ConnectionLost if value == 2 else CommunicationError  # 2: eof
    if category in ("asio.netdb", "asio.addrinfo"):
        return HostNotFound
    return Iec61850Error


def _make_error(category: str, value: int, message: str) -> BaseException:
    if category in ("system", "generic", "asio.system") and value == _errno.ENOMEM:
        return MemoryError(message)
    cls = error_class_for(category, value)
    exc = cls(message, category=category, code=value)
    if isinstance(exc, OSError) and category in ("system", "generic", "asio.system"):
        exc.errno = value
    return exc
