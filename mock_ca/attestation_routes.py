# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Env → :class:`libattest.ra.ProfileRegistry` wiring for the MockCA.

The per-OID attestation *route* logic — binding each attestation type to its
format codecs, verifier, and respInfo builder — now lives in the protocol-
agnostic :mod:`libattest.ra` engine (``AttestationProfile`` / ``ProfileRegistry``
+ the ``tpm_profile`` / ``jwt_profile`` factories).  The MockCA only keeps the
**environment wiring**: it reads ``VERIFIER_OID_ROUTES`` / ``VERIFIER_URL_FALLBACK``
/ ``TPM_QUOTE_PCRS`` / ``TPM_PCR_SELECTION_OID`` / ``TPM_KEY_ATTEST_OID`` and
builds a :class:`~libattest.ra.ProfileRegistry` from them.

Two kinds of profile are seeded:

1. the **TPM platform (quote) profile** — request type ``TPM_PCR_SELECTION_OID``,
   statement ``TcgAttestQuote`` (``2.23.133.20.2``), respInfo =
   ``TpmAttestationParams`` carrying the configured PCR set + negotiated hash;
2. the **TPM key-attestation (certify) profile** — request type
   ``TPM_KEY_ATTEST_OID``, statement ``TcgAttestCertify`` (``2.23.133.20.1``),
   no respInfo;

plus a **``jwt_profile``** for any *other* OID in ``VERIFIER_OID_ROUTES`` with no
built-in handler (sw/EAR shapes) — adding such a type is pure configuration.

Adding or replacing a verifier / reference-value service is a registration in
``libattest.ra`` (``AttestationProfile``'s ``verifier`` / ``reference_handler``
or the ``ServiceRegistry``), never a MockCA edit.
"""

from __future__ import annotations

import logging
import os

from libattest.formats.tpm import resolve_tpm_pcr_selection_oid
from libattest.ra import (
    ID_TCG_ATTEST_CERTIFY,
    ID_TCG_ATTEST_QUOTE,
    ProfileRegistry,
    jwt_profile,
    tpm_profile,
)

from mock_ca.verifier_registry import VerifierRegistry

logger = logging.getLogger(__name__)

# OID under which the EAR JWT is embedded as an X.509 extension on the issued
# cert (raw-JWT extnValue by default; CMW-wrapped when ``EAR_OID`` is id-pe-cmw).
# Each profile binds its own EAR encoder to this OID inside ``libattest.ra``.
_DEFAULT_EAR_EXT_OID: str = os.environ.get("EAR_OID", "1.7.6.5.123")


def _parse_pcr_list_env(value: str) -> list[int]:
    """Parse ``TPM_QUOTE_PCRS`` (e.g. ``"0,1,2,3,4"``) into a list of ints.

    Empty / invalid entries are dropped with a warning; an empty or unparseable
    value falls back to ``[0, 1, 2, 3, 4]`` so a typo never breaks startup.
    """
    fallback = [0, 1, 2, 3, 4]
    if not value:
        return fallback
    out: list[int] = []
    for tok in value.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            n = int(tok)
        except ValueError:
            logger.warning("TPM_QUOTE_PCRS: ignoring non-integer entry %r", tok)
            continue
        if n < 0:
            logger.warning("TPM_QUOTE_PCRS: ignoring negative PCR index %d", n)
            continue
        out.append(n)
    return out or fallback


def build_profile_registry_from_environment(
    verifier_registry: VerifierRegistry | None = None,
    tpm_quote_pcrs: list[int] | None = None,
) -> ProfileRegistry:
    """Build a :class:`libattest.ra.ProfileRegistry` from MockCA env vars.

    The raw OID→URL resolution is delegated to *verifier_registry* (built from
    ``VERIFIER_OID_ROUTES`` / ``VERIFIER_URL_FALLBACK`` when not supplied); the
    resolved URLs are handed to the ``libattest.ra`` profile factories, which own
    the default :class:`~libattest.ra.VeraisonVerifierClient` construction.

    Returns a registry indexing each profile by both its request-type OID
    (nonce-issue side) and its statement OID (evidence side).
    """
    registry = verifier_registry or VerifierRegistry.from_environment()
    pcrs = list(
        tpm_quote_pcrs
        if tpm_quote_pcrs is not None
        else _parse_pcr_list_env(os.environ.get("TPM_QUOTE_PCRS", "0,1,2,3,4"))
    )
    profiles = ProfileRegistry()

    # 1. TPM platform (quote) profile.  request_type = TPM_PCR_SELECTION_OID,
    #    statement = TcgAttestQuote; respInfo broadcasts the PCR set + the
    #    negotiated hash algorithm via the tpm_profile factory.
    quote_request_oid = resolve_tpm_pcr_selection_oid()
    quote_url = (
        registry.resolve_oid(ID_TCG_ATTEST_QUOTE) or registry.resolve_oid(quote_request_oid) or registry.fallback_url
    )
    if quote_url:
        profiles.register(
            tpm_profile(
                request_type_oid=quote_request_oid,
                statement_oid=ID_TCG_ATTEST_QUOTE,
                verifier_url=quote_url,
                pcrs=pcrs,
                resp_info_label="TpmAttestationParams",
                ear_oid=_DEFAULT_EAR_EXT_OID,
            )
        )
    else:
        logger.warning(
            "ProfileRegistry: no verifier URL for the TPM quote profile (request_type=%s, statement=%s); skipping it",
            quote_request_oid,
            ID_TCG_ATTEST_QUOTE,
        )

    # 2. TPM key-attestation (certify) profile.  request_type = TPM_KEY_ATTEST_OID
    #    (the syntax OID the client sends at GenM), statement = TcgAttestCertify;
    #    request_type and statement DIFFER, so an explicit register() is needed.
    #    Certify needs no PCR negotiation (pcrs=None → no respInfo), but its
    #    reqInfo still carries a TpmAttestationParams hash proposal, which
    #    tpm_profile parses.
    certify_request_oid = os.environ.get("TPM_KEY_ATTEST_OID", "1.3.6.1.4.1.99999.4")
    certify_url = (
        registry.resolve_oid(ID_TCG_ATTEST_CERTIFY)
        or registry.resolve_oid(certify_request_oid)
        or registry.fallback_url
    )
    if certify_url:
        profiles.register(
            tpm_profile(
                request_type_oid=certify_request_oid,
                statement_oid=ID_TCG_ATTEST_CERTIFY,
                verifier_url=certify_url,
                pcrs=None,
                resp_info_label="TcgAttestCertify",
                ear_oid=_DEFAULT_EAR_EXT_OID,
            )
        )
    else:
        logger.warning(
            "ProfileRegistry: no verifier URL for the certify profile (request_type=%s, statement=%s); skipping it",
            certify_request_oid,
            ID_TCG_ATTEST_CERTIFY,
        )

    # 3. jwt_profile for any extra OID configured but not built in (sw / EAR
    #    shapes).  A new opaque-evidence type is therefore pure config.
    for oid, url in registry.snapshot().get("oid_routes", {}).items():
        if profiles.by_request_type(oid) or profiles.by_statement(oid):
            continue
        profiles.register(
            jwt_profile(
                request_type_oid=oid,
                statement_oid=oid,
                verifier_url=url,
                ear_oid=_DEFAULT_EAR_EXT_OID,
            )
        )

    logger.info("MockCA ProfileRegistry initialised: %s", profiles.snapshot())
    return profiles


__all__ = [
    "ID_TCG_ATTEST_CERTIFY",
    "ID_TCG_ATTEST_QUOTE",
    "build_profile_registry_from_environment",
]
