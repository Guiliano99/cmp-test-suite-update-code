<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Missing Support Issue Template (Example: HSS Signatures)

The CMP test suite currently lacks support for Hierarchical Signature System (HSS) signatures as defined in RFC 8554 and RFC 9858. 
This includes the ability to parse, validate, and generate HSS signatures and keys. Adding this support is essential for testing 
CMP implementations that utilize HSS for post-quantum security.

## Motivation and Context

- HSS is a widely recognized stateful hash-based signature scheme, offering strong security guarantees.
- CMP implementations may adopt HSS for enhanced security, necessitating comprehensive test coverage.
- Supporting HSS aligns with our goal of providing robust post-quantum cryptographic testing capabilities.

## Desired Support
- Accept, generate, and validate HSS signatures using the parameter sets from RFC 8554, RFC 9858 and NIST SP 800-208.
- Track the HSS hierarchy depth correctly, enforcing `height < 9` and other constraints defined in NIST SP 800-208.

## Required Work Items

1. Extend parsing/validation logic to recognize HSS signature structures and keys.
2. Add regression fixtures (minimal + verbose) covering:
    - Valid signatures across permissible parameter sets.
    - Rejection cases for height ≥ 9, malformed hierarchies, and truncated signatures.
    - Mirror existing XMSS test cases where applicable.
    - Add basic test cases for a slow HSS variant for shake and SHA2 inside [pq_stateful_sig_tests.robot](tests_pq_and_hybrid/pq_stateful_sig_tests.robot).
3. Create verbose tests for all supported HSS combinations with the `scripts/generate_pq_stfl_test_cases.py` script and add it manually.
inside [pq_stateful_sig_alg.robot](tests_pq_and_hybrid/pq_stateful_sig_alg.robot).
4. Update documentation to reflect HSS support.

## Test Coverage

- Update **`ALGORITHM_TEST_COVERAGE.md`** to include HSS scenarios.

## Out of Scope/ Should be added later

(if applicable)

## Open Questions / Follow-ups

(if applicable)

## Implementation Notes

- `pyhsslms` supports the new SHAKE variants, but not key generation for height > 9.
- `hsslms` supports key generation for height > 9, but not the SHAKE variants.
- `liboqs-python` only supports verification of HSS signatures, but not signing or the SHAKE variants.

## References
- RFC 8554 — Leighton-Micali Hash-Based Signatures.
- RFC 9802 — Use of the HSS and XMSS Hash-Based Signature Algorithms in Internet X.509 PKI.
- RFC 9858 — Additional Parameter Sets for HSS/LMS Hash-Based Signatures.
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes.

---

# Missing Support Issue Template *(Example: Update NIST PQC Algorithms in X.509 Certificates and CMS)*

The CMP test suite currently lacks finished coverage for X.509 certificates that use the
NIST-standardized post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) with final LAMPS profiles.
This includes issuing, parsing, and validating certificates and PKIMessages that use these algorithms.

## Motivation and Context

* The final FIPS releases (203/204/205) are the baseline for PQC adoption in X.509 PKI.
* Several CMP flows rely on correct PQC certificate handling across Robot Framework suites
  and Python utilities.
* Aligning with the published LAMPS specifications keeps the suite interoperable with
  other PQC-enabled ecosystems.

## Desired Support

* Fix references to drafts inside the RF test cases.
* Check if the Robot Framework test cases cover all necessary scenarios and conditions.
* Add the test cases to the `SERVER_PQC_AND_HYBRID_TEST_COVERAGE.md` and
  `SERVER_ALGORITHM_TEST_COVERAGE.md` files.

## Required Work Items

1. Refresh `data/rfc_test_vectors/` to match the finalized RFC artifacts and unit tests, if needed.

2. **Validate existing test cases**
   Validate the existing Robot Framework test cases in `tests_pq_and_hybrid/` to ensure they cover:
    * Issuance of certificates with ML-KEM, ML-DSA, and SLH-DSA algorithms.
    * Parsing and validation of such certificates in various CMP message types
      (`P10CR`, `IR`, `CR`, `KUR`, `RR`).

3. **Add minimal examples**
   Add minimal examples inside
   [kem_tests.robot](tests_pq_and_hybrid/kem_tests.robot) and
   [pq_sig_tests.robot](tests_pq_and_hybrid/pq_sig_tests.robot).
   Use a configuration variable to define the default algorithm for all three supported PQC algorithms.

4. **Update generation scripts**
   Update
   [generate_alg_test_cases.py](scripts/generate_alg_test_cases.py) and
   [generate_pki_prot_tests.py](scripts/generate_pki_prot_tests.py)
   to generate verbose test cases for all three algorithms inside:

    * [kem_tests.robot](tests_pq_and_hybrid/kem_tests.robot)
    * [pq_sig_alg.robot](tests_pq_and_hybrid/pq_sig_alg.robot)
    * [pq_sig_pkiprotection.robot](tests_pq_and_hybrid/pq_sig_pkiprotection.robot)

5. **Add verbose parameter-set tests**
   Add verbose tests for all different parameter sets of ML-KEM, ML-DSA, and SLH-DSA algorithms inside:
    * [kem_alg.robot](tests_pq_and_hybrid/kem_alg.robot)
    * [pq_sig_alg.robot](tests_pq_and_hybrid/pq_sig_alg.robot)
    * [generate_pki_prot_tests.py](scripts/generate_pki_prot_tests.py)

6. **Run and verify with MockCA**
   Run the tests against MockCA, fix any issues found during testing, or open a new issue for later resolution.

7. Update the [REFERENCES.md](REFERENCES.md) to match the final RFCs.

## Should be added later

* Add Certificate Confirmation tests to check the usage of the correct hash algorithm
  inside the `certConf` messages and the correct acceptance with a returned `pkiconf` message.
  To perform this test, the CA must know which signing algorithm should be used,
  so for simplicity a new URL endpoint is advised. Unless there is a better solution.

* There is no official solution, so it is advised to use, for `SLH-DSA`, the hash algorithm
  defined in the CMS RFC. For `ML-DSA`, it is advised to use SHA-512 as the hash algorithm.

## Test Coverage

* Ensure Robot suites under `tests_pq_and_hybrid/` validate both
  acceptance and rejection paths for the final PQC certificate standards.
* Update **`ALGORITHM_TEST_COVERAGE.md`** and **`SERVER_TEST_COVERAGE.md`** to reflect the new PQC scenarios.

## Implementation Notes

* Existing test cases for draft versions of the algorithms should be reviewed and potentially adapted.
* Should wait until all RFCs are published.

## References

* **FIPS 203** — *Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).*
* **FIPS 204** — *Module-Lattice-Based Digital Signature Algorithm (ML-DSA).*
* **FIPS 205** — *Stateless Hash-Based Digital Signature Algorithm (SLH-DSA).*
* **RFC 9481** — *Certificate Management Protocol (CMP) Algorithms.*
* **RFC 9480** — *Certificate Management Protocol (CMP) Updates.*
* **RFC 9814** — *Use of the SLH-DSA Signature Algorithm in CMS.*
* **RFC 9882** — *Use of the ML-DSA Signature Algorithm in CMS.*

### Latest LAMPS Drafts

* `draft-ietf-lamps-kyber-certificates` *(in RFC Ed Queue)*
* `draft-ietf-lamps-dilithium-certificates` *(finished: RFC 9881)*
* `draft-ietf-lamps-sphincsplus-certificates` *(in RFC Ed Queue)*
* `draft-ietf-lamps-cms-kyber-13`: *Use of ML-KEM in CMS* *(RFC Ed Queue)*