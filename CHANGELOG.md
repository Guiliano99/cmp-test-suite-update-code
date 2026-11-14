<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Unreleased
- Run the test suites against the mock CA in CI, with the known failures tagged
- Run the Robot Framework dry run in CI
- Test the mock CA flows in-process, without opening a port
- Remove the imports from lower library modules into higher ones, and from production code into unit_tests
- Add a unit test that enforces the module layering
- Fix the 6 KEMBasedMAC tests (undefined `${key}`) and the 8 related-certificate tests (they posted to `/related-cert/p10cr`)
- Reject unknown arguments in the certificate request builders, so a misspelled argument no longer turns a negative test into a positive one
- Make `Exchange PKIMessage` honour its `add_pkibody_prefix` argument instead of the global `APPEND_PKIBODY_URL_SUFFIX`
- Make the Catalyst bad-POP mutator change the signature: the first-key POP was flipped twice and could become valid again
- Make `modify_random_str` never make a case-only change, so the negative issuer, subject, certProfile and MAC-sender tests always send a different value
- Read the decoded cA flag in `is_ca_cert` and `verify_ca_basic_constraints`, so a certificate with cA FALSE is no longer taken for a CA, and reject any pathLenConstraint with cA FALSE (RFC 5280 Section 4.2.1.9)
- Accept PQ signature certificates with keyUsage in the migration keyUsage check
- Write the KEK length in bits to the ECC-CMS-SharedInfo suppPubInfo (RFC 5753)
- Build a POPO from a bare signature algorithm OID, and use keyAgreement for X25519/X448 keys by default
- Read the p10cr CSR from the PKIBody in the keyword `Verify Signature POP For PKI Request`, which raised a KeyError for every p10cr
- Accept ccr wherever a body-name check tested for the nonexistent name crr: the request keywords, `/sun-hybrid`, and the Mock CA's compromised-key check
- Run each OpenSSL verification (`Verify Cert Chain OpenSSL` and the CRL check) in its own temporary directory, and raise BadConfig when the openssl binary cannot be run
- Mock CA: verify the signature POP of every request in a message, not only the first
- Mock CA: reject pvno 1 with unsupportedVersion, and answer an undecodable body on the hybrid routes with badDataFormat instead of HTTP 500
- Mock CA: verify a DH-based-MAC revocation request with the CA's key-agreement key
- Mock CA: honour `use_openssl` in the protection checks
- Mock CA: list revoked certificates on `/crl`, increase the CRL number, and give the stored revocation date and reason in CRLs and OCSP responses
- Mock CA: answer OCSP for a certificate replaced by a key update as revoked (reason superseded, dated at the update) instead of HTTP 500
- Mock CA: answer OCSP requests for unknown certificates with the status unknown, and stop adding the CRL-only IssuingDistributionPoint to issued certificates
- Mock CA: reject revoked certificates in the hybrid revocation checks, and compromised keys also for another subject and in a p10cr
- Mock CA: keep the failinfo of a rejected revocation entry, and serve `/cert/<serial>` as `application/pkix-cert`
- Rename the test "CA MUST Reject Protected Genm With Get CA Certs" to "CA MUST Respond To Protected Genm With Get CA Certs"
- Tag "CA MUST Reject Related Cert For Non-EE Cert" negative instead of positive, and correct its documentation
- Register the keyword "Validate certReqId" only once, drop the wrong failinfo declarations from the exceptions, and remove unused code
- Sign and verify the KGA `SignedData` over its signed attributes (RFC 5652 Section 5.4): the signature was computed and checked over the encoding of `encapContentInfo`, so the `SignedData` of a conformant CA did not verify
- Verify the KGA `SignedData` with the certificate that its `SignerIdentifier` names, and build and verify the structure with `pkixutils.cms`
- Remove the arguments `bad_sig`, `version` and `signer_infos` of `Prepare SignedData` and `Prepare SignerInfo`; a test that needs an invalid structure changes the result
- Mock CA: write `SignerInfo` version 1 when the KGA certificate has no SubjectKeyIdentifier and is named by issuer and serial number

# 0.0.2 - 2025-Apr-24
- Add PQ support

# 0.0.1 - 2024-Nov-20
- Initial release