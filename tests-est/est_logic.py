# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal logic for testing the Enrollment over Secure Transport (EST) protocol.

This module provides the small, dependency-light primitives that the
``tests-est`` Robot Framework suite needs to build, encode, decode and validate
EST messages *in depth*, without requiring a live EST server for the
message-level checks.

The implementation follows:

* RFC 7030  - Enrollment over Secure Transport (EST)
* RFC 8951  - Clarification of EST: Transfer Encodings and ASN.1
* RFC 8295  - EST (Enrollment over Secure Transport) Extensions
* RFC 7894  - Alternative Challenge Password Attributes for EST

Design notes
------------
* Heavy ASN.1/`pyasn1` parsing is imported lazily inside the functions that
  need it, so this module can be imported (and the path-/encoding-level
  keywords exercised) even in a stripped-down environment.
* Keyword names are exposed in Robot Framework style via ``@keyword`` so the
  ``.resource`` file and ``.robot`` suite read naturally.
"""

import base64
from typing import List, Optional, Tuple

from robot.api.deco import keyword, not_keyword

# ---------------------------------------------------------------------------
# RFC 7030 well-known constants
# ---------------------------------------------------------------------------

#: RFC 7030 Section 3.2.2 - the application uses the path prefix
#: "/.well-known/est" (RFC 5785 well-known URI).
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

#: RFC 7030 Section 3.2.4 / Section 4 - media types per operation.
#: Maps an operation to ``(request_content_type, response_content_type)``.
#: ``None`` means the message carries no body in that direction.
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
def est_content_type_matches(actual: str, expected: str) -> bool:  # noqa: D417
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
def decode_est_message_body(body: bytes) -> bytes:  # noqa: D417
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
    # Strip whitespace/newlines that base64.b64decode would otherwise reject.
    compact = b"".join(body.split())
    return base64.b64decode(compact)


# ---------------------------------------------------------------------------
# /simpleenroll and /simplereenroll bodies (RFC 7030 Section 4.2)
# ---------------------------------------------------------------------------


@keyword(name="Build EST Enroll Request Body")
def build_est_enroll_request_body(csr_der: bytes) -> bytes:  # noqa: D417
    """Wrap a PKCS#10 CSR (DER) into the base64 body used by /simpleenroll.

    RFC 7030 Section 4.2.1: the request is a single ``application/pkcs10`` PKCS#10
    structure, base64-encoded.

    Arguments:
    ---------
    - `csr_der`: The DER-encoded PKCS#10 ``CertificationRequest``.

    Returns:
    -------
        - The base64-encoded request body.

    Examples:
    --------
    | ${body}= | Build EST Enroll Request Body | ${csr_der} |

    """
    return encode_est_message_body(csr_der)


@keyword(name="Parse EST CACerts Response")
def parse_est_cacerts_response(body: bytes) -> List[bytes]:  # noqa: D417
    """Parse a /cacerts response into the list of contained certificates.

    RFC 7030 Section 4.1.3: a successful /cacerts response is a base64-encoded
    "certs-only" CMC Simple PKI Response - a degenerate CMS ``SignedData`` that
    carries only certificates and no ``signerInfos``.

    Arguments:
    ---------
    - `body`: The base64-encoded response body (as received over HTTP).

    Returns:
    -------
        - A list of DER-encoded X.509 certificates extracted from the bundle.

    Examples:
    --------
    | ${certs}= | Parse EST CACerts Response | ${response.content} |
    | Length Should Be | ${certs} | 1 |

    """
    der = decode_est_message_body(body)
    return _extract_certificates_from_cms(der)


@keyword(name="Parse EST Enroll Response")
def parse_est_enroll_response(body: bytes) -> List[bytes]:  # noqa: D417
    """Parse a /simpleenroll (or /simplereenroll) response into issued certificates.

    RFC 7030 Section 4.2.3: the response is a base64-encoded certs-only CMC
    Simple PKI Response containing the newly issued certificate.

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
    der = decode_est_message_body(body)
    return _extract_certificates_from_cms(der)


# ---------------------------------------------------------------------------
# /csrattrs (RFC 7030 Section 4.5)
# ---------------------------------------------------------------------------


@keyword(name="Parse EST CSR Attributes Response")
def parse_est_csrattrs_response(body: bytes) -> List[str]:  # noqa: D417
    """Parse a /csrattrs response into the list of requested attribute/OID strings.

    RFC 7030 Section 4.5.2: the response is a base64-encoded ``CsrAttrs`` - a
    ``SEQUENCE OF AttrOrOID`` describing the attributes/OIDs the server expects
    the client to include in its certification request.

    Arguments:
    ---------
    - `body`: The base64-encoded response body. An empty body / HTTP 204 means
      "no attributes required".

    Returns:
    -------
        - A list of dotted-OID strings (one per ``AttrOrOID`` entry).

    Examples:
    --------
    | ${oids}= | Parse EST CSR Attributes Response | ${response.content} |

    """
    if not body or not b"".join(bytes(body).split()):
        return []

    der = decode_est_message_body(body)

    # Lazy import: only this keyword needs pyasn1.
    from pyasn1.codec.der import decoder
    from pyasn1.type import univ

    # CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
    # AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
    seq, _ = decoder.decode(der, asn1Spec=univ.SequenceOf(componentType=univ.Any()))
    oids: List[str] = []
    for item in seq:
        inner, _ = decoder.decode(item.asOctets())
        if isinstance(inner, univ.ObjectIdentifier):
            oids.append(str(inner))
        else:
            # An Attribute is itself a SEQUENCE whose first element is the type OID.
            try:
                oids.append(str(inner[0]))
            except Exception:  # noqa: BLE001 - best-effort extraction
                oids.append(repr(inner))
    return oids


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


@not_keyword
def _extract_certificates_from_cms(cms_der: bytes) -> List[bytes]:
    """Extract DER certificates from a CMS certs-only ``SignedData`` (RFC 5652).

    Returns each certificate as DER bytes. Raises ``ValueError`` if the
    structure is not a CMS ``SignedData`` carrying certificates.
    """
    # Lazy import: keep the module importable without pyasn1 present.
    from pyasn1.codec.der import decoder, encoder
    from pyasn1_alt_modules import rfc5652

    content_info, _ = decoder.decode(cms_der, asn1Spec=rfc5652.ContentInfo())
    if content_info["contentType"] != rfc5652.id_signedData:
        raise ValueError("EST certs-only response is not a CMS SignedData structure.")

    signed_data, _ = decoder.decode(
        content_info["content"], asn1Spec=rfc5652.SignedData()
    )
    certificates = signed_data["certificates"]
    if not certificates.isValue or len(certificates) == 0:
        raise ValueError("EST certs-only response contains no certificates.")

    out: List[bytes] = []
    for choice in certificates:
        cert = choice.getComponent()
        out.append(encoder.encode(cert))
    return out
