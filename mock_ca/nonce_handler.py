# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""CMP-side nonce glue over the :mod:`libattest.ra` nonce store.

The reusable RA nonce lifecycle — generation, per-transaction storage keyed by
``(tx_id, statement-OID, instance)``, one-shot consume with replay/expiry
detection, and the ``respInfo`` carry — now lives in
:class:`libattest.ra.NonceStore`, driven by
:class:`libattest.ra.RemoteAttestationEngine`.  The MockCA no longer keeps its
own store.

This module retains only the *CMP-specific* glue:

* :func:`extract_transaction_id` — pull the CMP ``transactionID`` (the bytes the
  engine files nonces under) from a :class:`PKIMessageTMP`;
* :class:`SystemFailure` — the "no verifier route resolvable" error the MockCA's
  outer handler maps to CMP ``PKIFailureInfo: systemFailure`` (the engine itself
  raises no CMP errors).

The store/errors are re-exported from :mod:`libattest.ra` so callers that import
``ReplayError`` / ``NonceStore`` from here keep working.
"""

from __future__ import annotations

from libattest.ra import NonceState, NonceStore, ReplayError

__all__ = [
    "NonceState",
    "NonceStore",
    "ReplayError",
    "SystemFailure",
    "extract_transaction_id",
]


class SystemFailure(Exception):
    """Raised when no verifier route can be resolved for a request.

    The MockCA's outer error handler maps this to CMP
    ``PKIFailureInfo: systemFailure`` so the client knows the rejection is on
    the CA side, not a bad request.  (The deployment fails at startup when no
    routing is configured, so this is a last-resort guard.)
    """


def extract_transaction_id(pki_message) -> bytes:
    """Return the CMP ``transactionID`` bytes the nonce store keys on.

    The transactionID gates a transaction's nonces across the GenM (issue) and
    IR (consume) legs — the one CMP-specific identifier the engine needs.
    """
    return bytes(pki_message["header"]["transactionID"])
