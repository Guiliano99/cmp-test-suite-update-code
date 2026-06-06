"""Generate minimal, deterministic-enough EST test vectors used by tests-est/.

Produces:
  - data/est_ca_key.pem        : CA private key (RSA-2048)
  - data/est_ca_cert.pem       : self-signed CA certificate
  - data/est_cacerts.p7b       : RFC 7030 /cacerts response body
                                 (base64 of a CMS "certs-only" SignedData, as
                                  delivered with Content-Transfer-Encoding: base64)
  - data/est_simpleenroll.csr  : sample PKCS#10 request body for /simpleenroll
                                 (base64 DER, application/pkcs10)
"""
import base64
import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

OUT = pathlib.Path(__file__).resolve().parent
DATA = OUT
DATA.mkdir(parents=True, exist_ok=True)

# --- CA key + self-signed CA certificate -----------------------------------
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CMP Test Suite"),
    x509.NameAttribute(NameOID.COMMON_NAME, "EST Test Root CA"),
])
not_before = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
not_after = datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(0x7E57CA)
    .not_valid_before(not_before)
    .not_valid_after(not_after)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, key_cert_sign=True, crl_sign=True,
        content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
    .sign(ca_key, hashes.SHA256())
)

(DATA / "est_ca_key.pem").write_bytes(
    ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
(DATA / "est_ca_cert.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

# --- /cacerts response: CMS certs-only SignedData, base64 body --------------
# RFC 7030 4.1.3: response is a certs-only CMC Simple PKI Response (degenerate
# SignedData containing only certificates, no signerInfos).
p7_der = pkcs7.serialize_certificates([ca_cert], serialization.Encoding.DER)
b64 = base64.b64encode(p7_der).decode("ascii")
# wrap at 64 chars, as commonly transmitted under Content-Transfer-Encoding: base64
wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n"
(DATA / "est_cacerts.p7b").write_text(wrapped)

# --- /simpleenroll request body: PKCS#10, base64 DER ------------------------
ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "est-client.example.com"),
    ]))
    .sign(ee_key, hashes.SHA256())
)
csr_der = csr.public_bytes(serialization.Encoding.DER)
csr_b64 = base64.b64encode(csr_der).decode("ascii")
csr_wrapped = "\n".join(csr_b64[i:i + 64] for i in range(0, len(csr_b64), 64)) + "\n"
(DATA / "est_simpleenroll.csr").write_text(csr_wrapped)
(DATA / "est_client_key.pem").write_bytes(
    ee_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)

print("wrote:", *(p.name for p in sorted(DATA.iterdir())))  # noqa: T201 - generator CLI output
