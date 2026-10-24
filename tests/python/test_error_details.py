import pytest

import openiec61850 as iec
from openiec61850 import sync

from conftest import FAST

GET_NAME_LIST = 1
READ = 4
WRITE = 5
GET_NAMED_VARIABLE_LIST_ATTRIBUTES = 12


async def test_service_error_details(client, server):
    server.fail_next(READ, error_class=int(iec.ErrorClass.ACCESS), error_code=3, additional_code=42,
                     additional_description="locked by the operator", modifier_position=2)
    with pytest.raises(iec.AccessDenied) as info:
        await client.read("IED1LD0/MMXU1.TotW.mag.f[MX]")
    e = info.value
    assert e.error_class is iec.ErrorClass.ACCESS
    assert e.error_code == 3
    assert e.additional_code == 42
    assert e.additional_description == "locked by the operator"
    assert e.modifier_position == 2
    assert e.reject_type is None and e.reject_reason is None

    server.fail_next(GET_NAME_LIST, error_class=int(iec.ErrorClass.RESOURCE), error_code=1)
    with pytest.raises(iec.ServiceError) as info:
        await client.server_directory()
    e = info.value
    assert type(e) is iec.ServiceError
    assert e.error_class is iec.ErrorClass.RESOURCE
    assert e.error_code == 1
    assert e.additional_code is None and e.additional_description is None
    assert e.modifier_position is None

    # The details come from the request that failed inside a multi-request service.
    server.fail_next(GET_NAMED_VARIABLE_LIST_ATTRIBUTES, error_class=int(iec.ErrorClass.DEFINITION),
                     error_code=1, additional_code=7)
    with pytest.raises(iec.ObjectNotFound) as info:
        await client.enable_reporting("IED1LD0/LLN0.urcb01[RP]")
    assert info.value.additional_code == 7

    # A request that succeeds afterwards is unaffected.
    assert await client.read("IED1LD0/MMXU1.TotW.mag.f[MX]") == 1.5


async def test_reject_details(client, server):
    server.fail_next(WRITE, reject_reason=4)  # invalid-argument
    with pytest.raises(iec.RequestRejected) as info:
        await client.write("IED1LD0/MMXU1.TotW.mag.f[MX]", iec.Float32(2.0))
    e = info.value
    assert isinstance(e, iec.ServiceError)
    assert e.reject_type is iec.RejectType.CONFIRMED_REQUEST
    assert e.reject_reason == 4
    assert e.original_invoke_id is not None
    assert e.error_class is None


async def test_no_details_for_local_and_item_errors(client, server):
    with pytest.raises(iec.InvalidOperation) as info:
        await client.read("IED1LD0/MMXU1.TotW.mag.f")
    assert not hasattr(info.value, "error_class") or info.value.error_class is None
    results = await client.read_many(["IED1LD0/MMXU1.Nope[MX]"], return_exceptions=True)
    assert isinstance(results[0], iec.ObjectNotFound)
    assert results[0].error_class is None
    assert results[0].data_access_error == 10


async def test_control_refusal_details(client, server):
    ctl = await client.control("IED1LD1/GGIO1.SPCSO1")
    server.fail_next(WRITE, reject_reason=0)
    with pytest.raises(iec.RequestRejected) as info:
        await ctl.operate(True)
    assert info.value.reject_type is iec.RejectType.CONFIRMED_REQUEST

    server.fail_next(WRITE, error_class=int(iec.ErrorClass.ACCESS), error_code=3, additional_description="local")
    with pytest.raises(iec.AccessDenied) as info:
        await ctl.operate(True)
    assert info.value.additional_description == "local"


def test_sync_error_details(server):
    with sync.Client.connect("127.0.0.1", server.port, **FAST) as c:
        server.fail_next(READ, error_class=int(iec.ErrorClass.ACCESS), error_code=2, additional_code=5)
        with pytest.raises(iec.ObjectNotFound) as info:
            c.read("IED1LD0/MMXU1.TotW.mag.f[MX]")
        assert info.value.additional_code == 5
        assert info.value.error_class is iec.ErrorClass.ACCESS
