import openiec61850


def test_version():
    assert openiec61850.__version__ == "0.2.0"


def test_public_names_exist():
    for name in openiec61850.__all__:
        assert hasattr(openiec61850, name), name
