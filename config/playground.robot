# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation     Config file for running tests on the PKI playground.

*** Variables ***
${CA_CMP_URL}    https://signservice-playground.ct.siemens.com/ejbca/publicweb/cmp/PlaygroundMdcNameExtension
${CA_BASE_URL}    https://signservice-playground.ct.siemens.com/ejbca/publicweb/cmp/PlaygroundMdcNameExtension

# The initial issued certificate and key for running the tests.
${ISSUED_KEY}    ${None}
${ISSUED_CERT}   ${None}
# The initial issued certificate and key for running the tests setup.
${INIT_SUFFIX}   ${None}
${INITIAL_KEY_PATH}    ${None}
${INITIAL_CERT_PATH}   ${None}
${INITIAL_KEY_PASSWORD}   ${None}

# Test the LWCMP version.
${LWCMP}   ${True}
# Whether to enforce the algorithm to be set in the
# Algorithm Profile RFC9481.
# Does not affect the PQ signature algorithms.
# Only MAC and traditional signatures.
${ENFORCE_RFC9481}   ${True}

##### About Algorithms
${DEFAULT_KEY_LENGTH}    2048
${DEFAULT_ALGORITHM}    rsa
${DEFAULT_ECC_CURVE}   secp256r1
${DEFAULT_MAC_ALGORITHM}   password_based_mac
${DEFAULT_KGA_ALGORITHM}   rsa
${DEFAULT_PQ_SIG_ALGORITHM}   ml-dsa-44
${DEFAULT_PQ_KEM_ALGORITHM}   ml-kem-512
${DEFAULT_KEY_AGREEMENT_ALG}   x25519
${DEFAULT_KEY_ENCIPHERMENT_ALG}   ml-kem-768
${DEFAULT_ML_DSA_ALG}    ml-dsa-87
${DEFAULT_ML_KEM_ALG}    ml-kem-768

##### Extra Issuing Logic
${CA_RSA_ENCR_CERT}    ${None}
${CA_X25519_CERT}   ${None}
${CA_X448_CERT}     ${None}
${CA_ECC_CERT}      ${None}
${CA_HYBRID_KEM_CERT}   ${None}
${CA_KEM_CERT}     ${None}

##### About CertTemplate
${ALLOWED_ALGORITHM}   ed25519,rsa,ecc,ed448,x25519,x448,dsa
${ALLOW_ISSUING_OF_CA_CERTS}  ${True}
# Sensitive Service so maybe disallowed
${ALLOW_CMP_EKU_EXTENSION}  ${True}

##### Section 3
#Indicating if the PKIFailInfo must be set correctly.
${FAILINFO_MUST_BE_CORRECT}=    True
# For messageTime check.
${MAX_ALLOW_TIME_INTERVAL_RECEIVED}  ${-500}

# DSA is not allowed by RFC9483.
${DSA_KEY}         ${None}
${DSA_KEY_PASSWORD}   ${None}
${DSA_CERT}        ${None}

# Device certificate and key (None means not provided).
${DEVICE_CERT_CHAIN}   ${None}
${DEVICE_KEY}  ${None}
${DEVICE_KEY_PASSWORD}   ${None}

# Section 4.2
${REVOCATION_STRICT_CHECK}    ${False}
# The time to wait, until a certificate is revoked, so that
# the test cases can be run.
${REVOKED_WAIT_TIME}   5s
${UPDATE_WAIT_TIME}   3s
${WAIT_UNTIL_UPDATED_CONFIRMATION_IS_EXPIRED}   15s

# Section 5.2 and 5.3
# Other trusted PKI and Key (None means not provided, so test are skipped).
${OTHER_TRUSTED_PKI_KEY}    ${None}
${OTHER_TRUSTED_PKI_CERT}    ${None}
# Whether to allow unprotected inner messages, inside a nested PKIMessage.
${ALLOW_UNPROTECTED_INNER_MESSAGE}    ${None}
# The directory containing the certificates to build the trusted RA certificate chain.
${RA_CERT_CHAIN_DIR}    ${None}
# saves the entire certificate chain of the RA.
${RA_CERT_CHAIN_PATH}   ${None}

# A certificate used to verify, if it is supported
# that another trusted PKI Management Entity can revoke a certificate.
${RR_CERT_FOR_TRUSTED}   ${None}

# Relevant for CRR requests.
${TRUSTED_CA_CERT}      ${None}
${TRUSTED_CA_KEY}       ${None}
${TRUSTED_CA_KEY_PASSWORD}   ${None}
${TRUSTED_CA_DIR}            ${None}

# Hybrid Endpoints

${PQ_ISSUING_SUFFIX}    ${None}
${PQ_STATEFUL_ISSUING_SUFFIX}   ${None}
${URI_RELATED_CERT}   ${None}
${NEG_URI_RELATED_CERT}   ${None}
${ISSUING_SUFFIX}    ${None}
${COMPOSITE_URL_PREFIX}    ${None}
${CATALYST_SIGNATURE}    ${None}
${SUN_HYBRID_SUFFIX}    ${None}
${CHAMELEON_SUFFIX}    ${None}
${RELATED_CERT_SUFFIX}    ${None}
${MULTI_AUTH_SUFFIX}    ${None}
${CERT_DISCOVERY_SUFFIX}    ${None}