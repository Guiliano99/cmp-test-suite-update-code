<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Key Generation

This context covers how the test suite creates keys, and how that logic is being moved from the
local `resources/` modules into the standalone `keyutils-py` package.

## Language

**Key Generation Function**:
The single public entry point for creating private keys, `generate_key` in `resources/keyutils.py`,
exposed to Robot Framework as the `Generate Key` keyword. It dispatches traditional and
post-quantum algorithms and is the contract the 59 RF call sites and the unit tests rely on.
_Avoid_: "the key generator", "keygen"

**Delegated Key Generation**:
Key creation performed inside the standalone `keyutils-py` package instead of the host's local
factory. In the first migration slice only PQ/hybrid by-name key generation is delegated.
_Avoid_: "the new generate_key"

**Traditional Key Generation**:
Key creation for algorithms outside the post-quantum space (RSA, DSA, EC, EdDSA, X25519/X448,
Diffie-Hellman, RSA-KEM). It remains local to the host in the first migration slice, including
the deterministic `seed=` path.
_Avoid_: "classic keys"

**Post-Quantum Key Generation**:
Key creation for every key type (traditional, PQ signatures, PQ KEMs, post-quantum
stateful-hash signatures, hybrid keys). It is done by `keyutils-py`; `Generate Key` is its keyword.
_Avoid_: "PQC keys" (ambiguous: it does not say where the key is generated)

**Key Wrapper**:
The class family of `keyutils-py` that wraps a raw cryptographic key (serialization, SPKI,
signing, KEM operations). The suite has no wrapper classes of its own; it imports every key type
from `keyutils_py.types`, so a key from any source is an instance of the same classes.
_Avoid_: "the key object" (does not say which family)
