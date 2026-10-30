"""TLS through the Python API, against the native server over loopback."""

import datetime
import ipaddress

import pytest

import openiec61850 as iec
from openiec61850 import FC, BasicType as B

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, key, issuer_cn, issuer_key, ca=False, ip=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ip:
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _write(path, cert, key):
    cert_path, key_path = path.with_suffix(".pem"), path.with_suffix(".key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


@pytest.fixture
def pki(tmp_path):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("root", ca_key, "root", ca_key, ca=True)
    ca_file, _ = _write(tmp_path / "root", ca, ca_key)

    def issue(cn, ip=None):
        key = ec.generate_private_key(ec.SECP256R1())
        return _write(tmp_path / cn, _cert(cn, key, "root", ca_key, ip=ip), key)

    server_cert, server_key = issue("ied1", ip="127.0.0.1")
    client_cert, client_key = issue("hmi")
    return (
        iec.TlsConfig(ca_file=ca_file, certificate_file=server_cert, private_key_file=server_key),
        iec.TlsConfig(ca_file=ca_file, certificate_file=client_cert, private_key_file=client_key),
    )


def _model():
    b = iec.ModelBuilder()
    ld = b.logical_device("IED1LD0")
    ld.logical_node("LLN0").data_object("Mod").attribute("stVal", FC.ST, B.ENUMERATED, value=1)
    return b.build()


async def test_mutual_tls_round_trip(pki):
    server_tls, client_tls = pki
    requests = []

    def authorize(request):
        requests.append(request)
        return True

    async with await iec.Server.start(_model(), "127.0.0.1", 0, tls=server_tls, authorize=authorize) as s:
        async with await iec.Client.connect("127.0.0.1", s.port, tls=client_tls) as c:
            info = c.association_info
            assert info.tls.peer_subject == "CN=ied1"
            assert info.tls.peer_issuer == "CN=root"
            assert await c.server_directory() == ["IED1LD0"]
        assert requests[0].tls.peer_subject == "CN=hmi"
        assert len(requests[0].tls.peer_fingerprint_sha256) == 64


async def test_plain_association_has_no_tls_session():
    async with await iec.Server.start(_model(), "127.0.0.1", 0) as s:
        async with await iec.Client.connect("127.0.0.1", s.port) as c:
            assert c.association_info.tls is None


async def test_wrong_peer_name_is_a_tls_error(pki):
    server_tls, client_tls = pki
    wrong = iec.TlsConfig(**{**vars(client_tls), "peer_name": "other.local"})
    async with await iec.Server.start(_model(), "127.0.0.1", 0, tls=server_tls) as s:
        with pytest.raises(iec.TlsError):
            await iec.Client.connect("127.0.0.1", s.port, tls=wrong, timeout=2)


async def test_plain_client_cannot_associate_with_a_tls_server(pki):
    server_tls, _ = pki
    async with await iec.Server.start(_model(), "127.0.0.1", 0, tls=server_tls) as s:
        with pytest.raises(iec.CommunicationError):
            await iec.Client.connect("127.0.0.1", s.port, timeout=2)


async def test_unusable_configuration_is_reported_when_starting(pki, tmp_path):
    server_tls, _ = pki
    missing = iec.TlsConfig(**{**vars(server_tls), "certificate_file": tmp_path / "absent.pem"})
    with pytest.raises(iec.TlsError):
        await iec.Server.start(_model(), "127.0.0.1", 0, tls=missing)
    with pytest.raises(ValueError):
        await iec.Server.start(_model(), "127.0.0.1", 0, tls=iec.TlsConfig(ca_file=server_tls.ca_file))


def test_private_key_password_stays_out_of_repr():
    assert "s3cret" not in repr(iec.TlsConfig(private_key_password="s3cret"))
