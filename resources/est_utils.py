# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Enrollment over Secure Transport (EST) protocol logic.

A real, dependency-light implementation of the EST message layer built on top
of the existing CMP-Test-Suite utilities (``certbuildutils``, ``certutils``,
``envdatautils``, ``keyutils``). It is shared by both sides of the protocol:

* the **client** (the ``tests-est`` Robot suite) uses it to build requests and
  parse responses, and
* the **server** (``mock_ca.est_handler.EstHandler``) uses it to assemble the
  ``certs-only`` responses it returns.

Specifications:

* RFC 7030 - Enrollment over Secure Transport (EST)
* RFC 8951 - Clarification of EST: Transfer Encodings and ASN.1
* RFC 8295 - EST (Enrollment over Secure Transport) Extensions
* RFC 7894 - Alternative Challenge Password Attributes for EST
* RFC 5272 - Certificate Management over CMS (the "certs-only" Simple PKI Response)
* RFC 5652 - Cryptographic Message Syntax (CMS)

Heavy suite modules are imported lazily inside the functions that need them, so
the pure protocol helpers (URL layout, transfer encoding, content types) remain
usable in a stripped-down environment.
"""

import base64
from typing import List, Optional, Tuple, Union

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5652, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

# ---------------------------------------------------------------------------
# RFC 7030 well-known constants
# ---------------------------------------------------------------------------

#: RFC 7030 Section 3.2.2 - the application path prefix (RFC 5785 well-known URI).
EST_WELL_KNOWN_PREFIX = "/.well-known/est"

#: RFC 7030 Section 3.2.2 - the defined EST operation path components.
EST_OPERATIONS = (
    "cacerts",
    "simpleenroll",
    "simplereenroll",
    "fullcmc",
    "serverkeygen",
    "csrattrs",
)

#: RFC 7030 Section 3.2.4 / Section 4 - media types per operation, as
#: ``(request_content_type, response_content_type)``. ``None`` means no body in
#: that direction.
EST_CONTENT_TYPES = {
    "cacerts": (None, "application/pkcs7-mime"),
    "simpleenroll": ("application/pkcs10", "application/pkcs7-mime"),
    "simplereenroll": ("application/pkcs10", "application/pkcs7-mime"),
    "fullcmc": ("application/pkcs7-mime", "application/pkcs7-mime"),
    "serverkeygen": ("application/pkcs10", "multipart/mixed"),
    "csrattrs": (None, "application/csrattrs"),
}


# ---------------------------------------------------------------------------
# URL / path construction (RFC 7030 Section 3.2.2)
# ---------------------------------------------------------------------------


@keyword(name="Get EST Endpoint URL")
def get_est_endpoint_url(  # noqa: D417 for RF docs
    base_url: str,
    operation: str,
    label: Optional[str] = None,
) -> str:
    """Build the full URL of an EST endpoint.

    Implements the path layout of RFC 7030 Section 3.2.2::

        https://<host>[:<port>]/.well-known/est[/<label>]/<operation>

    Arguments:
    ---------
    - `base_url`: Scheme + authority of the EST server, e.g. ``https://ca.example``.
    - `operation`: One of the EST operations (e.g. ``cacerts``, ``simpleenroll``).
    - `label`: Optional additional path segment (RFC 7030 Section 3.2.2) used to
      select a CA or enrollment profile. ``None`` means no label.

    Returns:
    -------
        - The fully-qualified EST endpoint URL.

    Raises:
    ------
        - ValueError: If `operation` is not a known EST operation.

    Examples:
    --------
    | ${url}= | Get EST Endpoint URL | https://ca.test | cacerts |
    | ${url}= | Get EST Endpoint URL | https://ca.test | simpleenroll | label=RSA |

    """
    if operation not in EST_OPERATIONS:
        raise ValueError(
            f"Unknown EST operation '{operation}'. Expected one of: {', '.join(EST_OPERATIONS)}"
        )

    base = base_url.rstrip("/")
    if label:
        label = label.strip("/")
        return f"{base}{EST_WELL_KNOWN_PREFIX}/{label}/{operation}"
    return f"{base}{EST_WELL_KNOWN_PREFIX}/{operation}"


# ---------------------------------------------------------------------------
# Content-type handling (RFC 7030 Section 3.2.4)
# ---------------------------------------------------------------------------


@keyword(name="Get EST Content Types")
def get_est_content_types(operation: str) -> Tuple[Optional[str], Optional[str]]:  # noqa: D417
    """Return the ``(request, response)`` media types for an EST operation.

    Arguments:
    ---------
    - `operation`: One of the EST operations.

    Returns:
    -------
        - A tuple ``(request_content_type, response_content_type)``; a member is
          ``None`` when no body is carried in that direction.

    Examples:
    --------
    | ${req} | ${resp}= | Get EST Content Types | simpleenroll |

    """
    if operation not in EST_CONTENT_TYPES:
        raise ValueError(f"Unknown EST operation '{operation}'.")
    return EST_CONTENT_TYPES[operation]


@keyword(name="EST Content Type Matches")
def est_content_type_matches(actual: Optional[str], expected: str) -> bool:  # noqa: D417
    """Check whether a received ``Content-Type`` matches an expected media type.

    The comparison ignores any parameters (e.g. ``; smime-type=certs-only`` or
    ``; boundary=...``) and is case-insensitive, as required by RFC 7030 /
    RFC 7231.

    Arguments:
    ---------
    - `actual`: The ``Content-Type`` header value received from the server.
    - `expected`: The bare media type expected for the operation.

    Returns:
    -------
        - ``True`` if the media types match, ``False`` otherwise.

    Examples:
    --------
    | ${ok}= | EST Content Type Matches | application/pkcs7-mime; smime-type=certs-only | application/pkcs7-mime |

    """
    if actual is None:
        return False
    actual_type = actual.split(";", 1)[0].strip().lower()
    return actual_type == expected.split(";", 1)[0].strip().lower()


# ---------------------------------------------------------------------------
# Transfer encoding (RFC 7030 Section 3.2 / RFC 8951)
# ---------------------------------------------------------------------------


@keyword(name="Encode EST Message Body")
def encode_est_message_body(der_data: bytes, line_length: int = 64) -> bytes:  # noqa: D417
    """Base64-encode a DER payload for transport with ``Content-Transfer-Encoding: base64``.

    RFC 7030 Section 3.2 and RFC 8951 require EST payloads to be base64-encoded
    (without the surrounding PEM/CMC headers) when sent over HTTP.

    Arguments:
    ---------
    - `der_data`: The raw DER-encoded message (PKCS#10, CMS, ...).
    - `line_length`: Optional max line length for wrapping (0 = no wrapping).

    Returns:
    -------
        - The base64-encoded body as ``bytes`` (ASCII).

    Examples:
    --------
    | ${body}= | Encode EST Message Body | ${der} |

    """
    b64 = base64.b64encode(der_data).decode("ascii")
    if line_length and line_length > 0:
        b64 = "\n".join(b64[i : i + line_length] for i in range(0, len(b64), line_length))
    return b64.encode("ascii")


@keyword(name="Decode EST Message Body")
def decode_est_message_body(body: Union[bytes, str]) -> bytes:  # noqa: D417
    """Base64-decode an EST HTTP body back into raw DER.

    Tolerates the line wrapping commonly applied under
    ``Content-Transfer-Encoding: base64`` (RFC 8951).

    Arguments:
    ---------
    - `body`: The base64-encoded body (``bytes`` or ``str``).

    Returns:
    -------
        - The decoded DER bytes.

    Examples:
    --------
    | ${der}= | Decode EST Message Body | ${response.content} |

    """
    if isinstance(body, str):
        body = body.encode("ascii")
    compact = b"".join(body.split())
    return base64.b64decode(compact)


# ---------------------------------------------------------------------------
# PKCS#10 client requests (RFC 7030 Section 4.2 / 4.4)
# ---------------------------------------------------------------------------


@keyword(name="Build EST CSR")
def build_est_csr(  # noqa: D417
    signing_key,
    common_name: str = "CN=EST Test Client",
    **kwargs,
) -> rfc6402.CertificationRequest:
    """Build a PKCS#10 ``CertificationRequest`` for an EST enrollment.

    Thin wrapper around ``certbuildutils.build_csr`` so the EST suite reuses the
    suite's existing, well-tested CSR construction.

    Arguments:
    ---------
    - `signing_key`: The private key that signs (and is certified by) the CSR.
    - `common_name`: The subject DN in OpenSSL notation.
    - `kwargs`: Forwarded to ``certbuildutils.build_csr`` (e.g. ``subjectAltName``).

    Returns:
    -------
        - The populated ``CertificationRequest``.

    Examples:
    --------
    | ${csr}= | Build EST CSR | ${key} | CN=est-client.example.com |

    """
    from resources import certbuildutils  # lazy: heavy import

    return certbuildutils.build_csr(signing_key=signing_key, common_name=common_name, **kwargs)


@keyword(name="Build EST Enroll Request Body")
def build_est_enroll_request_body(csr: Union[bytes, rfc6402.CertificationRequest]) -> bytes:  # noqa: D417
    """Encode a PKCS#10 CSR into the base64 body used by /simpleenroll.

    RFC 7030 Section 4.2.1: the request is a single ``application/pkcs10`` PKCS#10
    structure, base64-encoded.

    Arguments:
    ---------
    - `csr`: Either the DER-encoded CSR (``bytes``) or a ``CertificationRequest``.

    Returns:
    -------
        - The base64-encoded request body.

    Examples:
    --------
    | ${body}= | Build EST Enroll Request Body | ${csr} |

    """
    if not isinstance(csr, (bytes, bytearray)):
        csr = encoder.encode(csr)
    return encode_est_message_body(bytes(csr))


# ---------------------------------------------------------------------------
# certs-only CMS responses (RFC 5272 / RFC 7030 Section 4.1.3, 4.2.3)
# ---------------------------------------------------------------------------


@not_keyword
def _coerce_cert(cert: Union[bytes, rfc9480.CMPCertificate]) -> rfc9480.CMPCertificate:
    """Return a ``CMPCertificate`` from DER bytes or pass an existing one through."""
    if isinstance(cert, (bytes, bytearray)):
        from resources import certutils  # lazy

        return certutils.parse_certificate(bytes(cert))
    return cert


@keyword(name="Build EST Certs Only Message")
def build_est_certs_only_message(  # noqa: D417 for RF docs
    certs: Union[bytes, rfc9480.CMPCertificate, List[Union[bytes, rfc9480.CMPCertificate]]],
) -> bytes:
    """Build a DER ``certs-only`` CMS message (RFC 5272 Simple PKI Response).

    RFC 7030 Sections 4.1.3 / 4.2.3: both /cacerts and the enrollment responses
    are a base64-encoded "certs-only" structure - a degenerate CMS ``SignedData``
    (RFC 5652 Section 5.1) that carries only certificates: empty
    ``digestAlgorithms``, an ``encapContentInfo`` of type id-data with no content,
    the certificates, and no ``signerInfos``.

    Reuses ``envdatautils.prepare_certificate_set`` for the certificate set.

    Arguments:
    ---------
    - `certs`: A certificate or list of certificates (``CMPCertificate`` or DER).

    Returns:
    -------
        - The DER-encoded ``ContentInfo`` wrapping the certs-only ``SignedData``.

    Examples:
    --------
    | ${der}= | Build EST Certs Only Message | ${ca_cert} |

    """
    from resources import envdatautils  # lazy

    if not isinstance(certs, list):
        certs = [certs]
    cert_objs = [_coerce_cert(c) for c in certs]

    signed_data = rfc5652.SignedData()
    signed_data["version"] = 1
    # digestAlgorithms: empty SET (no signers).
    signed_data["digestAlgorithms"].clear()

    encap = rfc5652.EncapsulatedContentInfo()
    encap["eContentType"] = rfc5652.id_data  # no eContent for certs-only
    signed_data["encapContentInfo"] = encap

    signed_data["certificates"] = envdatautils.prepare_certificate_set(cert_objs)
    # signerInfos: left as an empty SET.

    content_info = rfc5652.ContentInfo()
    content_info["contentType"] = rfc5652.id_signedData
    content_info["content"] = encoder.encode(signed_data)
    return encoder.encode(content_info)


@not_keyword
def _extract_certificates_from_cms(cms_der: bytes) -> List[bytes]:
    """Extract DER certificates from a CMS certs-only ``SignedData`` (RFC 5652).

    Note: this intentionally does not reuse ``ca_kga_logic.get_certificates_from_signed_data``.
    That helper builds/orders a certificate *chain* and returns ``CMPCertificate``
    objects, whereas EST callers just want every contained certificate as raw DER,
    in order, without chain logic - and we keep this module's import footprint light.
    """
    content_info, _ = decoder.decode(cms_der, asn1Spec=rfc5652.ContentInfo())
    if content_info["contentType"] != rfc5652.id_signedData:
        raise ValueError("EST certs-only response is not a CMS SignedData structure.")

    signed_data, _ = decoder.decode(content_info["content"], asn1Spec=rfc5652.SignedData())
    certificates = signed_data["certificates"]
    if not certificates.isValue or len(certificates) == 0:
        raise ValueError("EST certs-only response contains no certificates.")

    out: List[bytes] = []
    for choice in certificates:
        cert = choice.getComponent()
        out.append(encoder.encode(cert))
    return out


@not_keyword
def _decode_and_extract_certs(body: Union[bytes, str]) -> List[bytes]:
    """Base64-decode a certs-only EST body and return the contained certificates as DER."""
    der = decode_est_message_body(body)
    return _extract_certificates_from_cms(der)


@keyword(name="Parse EST CACerts Response")
def parse_est_cacerts_response(body: Union[bytes, str]) -> List[bytes]:  # noqa: D417
    """Parse a /cacerts response into the list of contained certificates.

    RFC 7030 Section 4.1.3.

    Arguments:
    ---------
    - `body`: The base64-encoded response body (as received over HTTP).

    Returns:
    -------
        - A list of DER-encoded X.509 certificates extracted from the bundle.

    Examples:
    --------
    | ${certs}= | Parse EST CACerts Response | ${response.content} |

    """
    return _decode_and_extract_certs(body)


@keyword(name="Parse EST Enroll Response")
def parse_est_enroll_response(body: Union[bytes, str]) -> List[bytes]:  # noqa: D417
    """Parse a /simpleenroll (or /simplereenroll) response into issued certificates.

    RFC 7030 Section 4.2.3. The response uses the same ``certs-only`` structure as
    /cacerts, so this delegates to the same extraction.

    Arguments:
    ---------
    - `body`: The base64-encoded response body.

    Returns:
    -------
        - A list of DER-encoded issued certificates (normally exactly one).

    Examples:
    --------
    | ${certs}= | Parse EST Enroll Response | ${response.content} |

    """
    return _decode_and_extract_certs(body)


@keyword(name="Parse EST Certificate")
def parse_est_certificate(cert_der: bytes) -> rfc9480.CMPCertificate:  # noqa: D417
    """Parse a DER certificate into a ``CMPCertificate`` using the suite parser.

    Arguments:
    ---------
    - `cert_der`: The DER-encoded certificate.

    Returns:
    -------
        - The parsed ``CMPCertificate``.

    """
    from resources import certutils  # lazy

    return certutils.parse_certificate(cert_der)


# ---------------------------------------------------------------------------
# /csrattrs (RFC 7030 Section 4.5)
# ---------------------------------------------------------------------------


@keyword(name="Build EST CSR Attributes")
def build_est_csr_attributes(oids: Optional[List[str]] = None) -> bytes:  # noqa: D417
    """Build a DER ``CsrAttrs`` structure (RFC 7030 Section 4.5.2).

    ``CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID``. This builder emits the
    OID-only form (``AttrOrOID`` choosing ``oid``), which is sufficient to tell a
    client which attributes/OIDs it should include in its certification request.

    Arguments:
    ---------
    - `oids`: Dotted OID strings to advertise. ``None`` / empty yields an empty
      ``CsrAttrs`` (the server requires no extra attributes).

    Returns:
    -------
        - The DER-encoded ``CsrAttrs``.

    Examples:
    --------
    | ${der}= | Build EST CSR Attributes | ${{ ['1.2.840.113549.1.9.7'] }} |

    """
    seq = univ.SequenceOf(componentType=univ.Any())
    for oid in oids or []:
        seq.append(univ.Any(encoder.encode(univ.ObjectIdentifier(oid))))
    return encoder.encode(seq)


@keyword(name="Parse EST CSR Attributes Response")
def parse_est_csrattrs_response(body: Union[bytes, str]) -> List[str]:  # noqa: D417
    """Parse a /csrattrs response into the list of requested attribute/OID strings.

    RFC 7030 Section 4.5.2: the response is a base64-encoded ``CsrAttrs`` - a
    ``SEQUENCE OF AttrOrOID``. An empty body / HTTP 204 means "no attributes
    required".

    Arguments:
    ---------
    - `body`: The base64-encoded response body.

    Returns:
    -------
        - A list of dotted-OID strings (one per ``AttrOrOID`` entry).

    Examples:
    --------
    | ${oids}= | Parse EST CSR Attributes Response | ${response.content} |

    """
    if isinstance(body, str):
        body = body.encode("ascii")
    if not body or not body.split():
        return []

    try:
        der = decode_est_message_body(body)
        seq, _ = decoder.decode(der, asn1Spec=univ.SequenceOf(componentType=univ.Any()))
    except Exception as exc:  # noqa: BLE001 - turn base64/ASN.1 errors into a clean failure
        raise ValueError(f"Response is not a valid base64-encoded CsrAttrs structure: {exc}") from exc

    oids: List[str] = []
    for item in seq:
        inner, _ = decoder.decode(item.asOctets())
        if isinstance(inner, univ.ObjectIdentifier):
            oids.append(str(inner))
        else:
            # An Attribute is a SEQUENCE whose first element is the type OID.
            try:
                oids.append(str(inner[0]))
            except Exception:  # noqa: BLE001 - best-effort extraction
                oids.append(repr(inner))
    return oids


# ---------------------------------------------------------------------------
# /serverkeygen (RFC 7030 Section 4.4)
# ---------------------------------------------------------------------------

_SERVERKEYGEN_BOUNDARY = "estServerKeyGenBoundary"


@keyword(name="Build EST Server Keygen Response")
def build_est_serverkeygen_response(  # noqa: D417
    private_key_der: bytes,
    cert: Union[bytes, rfc9480.CMPCertificate],
    boundary: str = _SERVERKEYGEN_BOUNDARY,
) -> Tuple[str, bytes]:
    """Build the multipart/mixed body for a /serverkeygen response.

    RFC 7030 Section 4.4.2: the response is ``multipart/mixed`` with two parts -
    the server-generated private key (``application/pkcs8``) and the issued
    certificate (``application/pkcs7-mime``, certs-only). Both are base64-encoded.

    This builder returns the unprotected PKCS#8 form of the private key; a real
    deployment MAY instead wrap it in CMS ``EnvelopedData``.

    Arguments:
    ---------
    - `private_key_der`: The server-generated private key as PKCS#8 DER.
    - `cert`: The issued certificate (``CMPCertificate`` or DER); wrapped certs-only.
    - `boundary`: The MIME multipart boundary.

    Returns:
    -------
        - ``(content_type, body)`` where ``content_type`` includes the boundary.

    Examples:
    --------
    | ${ct} | ${body}= | Build EST Server Keygen Response | ${key_der} | ${cert} |

    """
    key_b64 = encode_est_message_body(private_key_der)
    cert_cms = build_est_certs_only_message(cert)
    cert_b64 = encode_est_message_body(cert_cms)

    crlf = "\r\n"
    parts = (
        f"--{boundary}{crlf}"
        f"Content-Type: application/pkcs8{crlf}"
        f"Content-Transfer-Encoding: base64{crlf}{crlf}"
    ).encode("ascii")
    parts += key_b64 + crlf.encode("ascii")
    parts += (
        f"--{boundary}{crlf}"
        f"Content-Type: application/pkcs7-mime; smime-type=certs-only{crlf}"
        f"Content-Transfer-Encoding: base64{crlf}{crlf}"
    ).encode("ascii")
    parts += cert_b64 + crlf.encode("ascii")
    parts += f"--{boundary}--{crlf}".encode("ascii")

    content_type = f'multipart/mixed; boundary="{boundary}"'
    return content_type, parts


@keyword(name="Parse EST Server Keygen Response")
def parse_est_serverkeygen_response(  # noqa: D417
    content_type: str,
    body: bytes,
) -> Tuple[bytes, List[bytes]]:
    """Parse a /serverkeygen multipart/mixed response.

    Arguments:
    ---------
    - `content_type`: The response ``Content-Type`` header (carries the boundary).
    - `body`: The raw multipart body.

    Returns:
    -------
        - ``(private_key_der, certs)`` - the decoded PKCS#8 private key and the
          list of DER certificates from the certs-only part.

    Examples:
    --------
    | ${key} | ${certs}= | Parse EST Server Keygen Response | ${resp.headers}[Content-Type] | ${resp.content} |

    """
    boundary = None
    for param in content_type.split(";"):
        param = param.strip()
        if param.lower().startswith("boundary="):
            boundary = param.split("=", 1)[1].strip().strip('"')
            break
    if boundary is None:
        raise ValueError("multipart/mixed response is missing a boundary parameter.")

    if isinstance(body, str):
        body = body.encode("ascii")

    delimiter = ("--" + boundary).encode("ascii")
    raw_parts = [p for p in body.split(delimiter) if p.strip() not in (b"", b"--")]

    private_key_der: Optional[bytes] = None
    certs: List[bytes] = []
    for part in raw_parts:
        # Split headers from the (base64) payload at the first blank line.
        normalized = part.replace(b"\r\n", b"\n").strip(b"\n")
        if b"\n\n" not in normalized:
            continue
        headers_blob, payload = normalized.split(b"\n\n", 1)
        headers = headers_blob.decode("ascii", "replace").lower()
        der = decode_est_message_body(payload)
        if "application/pkcs8" in headers:
            private_key_der = der
        elif "application/pkcs7-mime" in headers:
            certs = _extract_certificates_from_cms(der)

    if private_key_der is None:
        raise ValueError("serverkeygen response did not contain an application/pkcs8 part.")
    return private_key_der, certs
