import os

import pytest

import openiec61850 as iec

try:
    from openiec61850 import _testing
except ImportError:  # release wheels do not ship the test-only extension
    _testing = None

REQUIRE_TESTING = os.environ.get("OPENIEC61850_REQUIRE_TESTING") == "1"


def pytest_collection_modifyitems(config, items):
    if _testing is not None:
        return
    if REQUIRE_TESTING:
        raise pytest.UsageError("OPENIEC61850_REQUIRE_TESTING=1 but openiec61850._testing is missing")
    skip = pytest.mark.skip(reason="built without OPENIEC61850_BUILD_PYTHON_TESTING")
    for item in items:
        if "server" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)


@pytest.fixture
def server():
    if _testing is None:
        pytest.fail("openiec61850._testing is not available")
    s = _testing.FakeServer()
    yield s
    s.close()


FAST = dict(timeout=2.0, request_timeout=2.0, release_timeout=1.0)


@pytest.fixture
async def client(server):
    c = await iec.Client.connect("127.0.0.1", server.port, **FAST)
    yield c
    if c.state != iec.ConnectionState.CLOSED:
        c.abort()
        await c.wait_closed()
