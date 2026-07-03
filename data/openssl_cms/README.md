<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# OpenSSL-generated `SignedData` fixtures

The DER files in this directory are CMS `SignedData` structures created with the
**OpenSSL command line tool** (an independent implementation) and are validated by
`unit_tests/tests_protocol_related/test_kga_logic/test_openssl_generated_signed_data.py`
via `resources.ca_kga_logic.validate_signed_data_structure`, to cross-check that the
test suite's KGA `SignedData` logic is implemented correctly.

## Files

| File | Description |
| --- | --- |
| `akp_rsa.der` | The signed eContent: an `AsymmetricKeyPackage` (RFC 5958) wrapping `data/keys/private-key-rsa.pem` as a v2 `OneAsymmetricKey` (with public key). Generated with the suite itself, because the OpenSSL CLI cannot emit v2 `OneAsymmetricKey` structures. |
| `signed_data_ecdsa.der` | `SignedData` signed with `data/unittest/kga_cert_kari_ecdsa.pem` (ECDSA P-256, SHA-256). |
| `signed_data_ml_dsa_65.der` | `SignedData` signed with a freshly generated ML-DSA-65 KGA certificate (SHA-512 digest). Requires OpenSSL >= 3.5. |
| `signed_data_slh_dsa_sha2_256f.der` | `SignedData` signed with a freshly generated SLH-DSA-SHA2-256f KGA certificate (SHA-512 digest). Requires OpenSSL >= 3.5. |
| `trustanchors/` | Root CA certificates for the freshly generated PQ chains (loaded as trust anchors by the test). |

## Generation commands

All commands are run from the repository root.

### 1. eContent (once)

```bash
PYTHONPATH=./resources python3 -c "
from pyasn1.codec.der import encoder
from resources.keyutils import load_private_key_from_file
from resources.envdatautils import prepare_asymmetric_key_package
key = load_private_key_from_file('data/keys/private-key-rsa.pem', password=None)
data = encoder.encode(prepare_asymmetric_key_package(private_keys=[key]))
open('data/openssl_cms/akp_rsa.der', 'wb').write(data)
"
```

### 2. ECDSA (reuses existing repository fixtures)

```bash
openssl cms -sign -binary -nodetach -outform DER \
  -in data/openssl_cms/akp_rsa.der \
  -out data/openssl_cms/signed_data_ecdsa.der \
  -signer data/unittest/kga_cert_kari_ecdsa.pem \
  -inkey data/keys/private-key-ecdsa.pem -passin pass:11111 \
  -certfile data/unittest/root_cert_ed25519.pem \
  -keyid -md sha256 -nosmimecap \
  -econtent_type 2.16.840.1.101.2.1.2.78.5
```

### 3. ML-DSA-65 and SLH-DSA-SHA2-256f (fresh root + KGA certificates)

The KGA certificate needs a `SubjectKeyIdentifier` (required by `-keyid`) and the
`cmKGA` extended key usage (`1.3.6.1.5.5.7.3.32`). The suite expects the SHA-512
digest for both algorithms.

```bash
cat > kga_ext.cnf <<'EOF'
[kga_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.32
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

for entry in "ML-DSA-65:ml_dsa_65" "SLH-DSA-SHA2-256f:slh_dsa_sha2_256f"; do
  alg=${entry%%:*}; name=${entry#*:}
  openssl genpkey -algorithm "$alg" -out "root_${name}_key.pem"
  openssl req -x509 -new -key "root_${name}_key.pem" \
    -subj "/CN=OpenSSL ${alg} Root CA" -days 3650 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "data/openssl_cms/trustanchors/root_${name}.pem"
  openssl genpkey -algorithm "$alg" -out "kga_${name}_key.pem"
  openssl req -new -key "kga_${name}_key.pem" -subj "/CN=OpenSSL ${alg} KGA" -out "kga_${name}.csr"
  openssl x509 -req -in "kga_${name}.csr" \
    -CA "data/openssl_cms/trustanchors/root_${name}.pem" \
    -CAkey "root_${name}_key.pem" \
    -set_serial 1 -days 3650 -extfile kga_ext.cnf -extensions kga_ext \
    -out "kga_${name}.pem"
  openssl cms -sign -binary -nodetach -outform DER \
    -in data/openssl_cms/akp_rsa.der \
    -out "data/openssl_cms/signed_data_${name}.der" \
    -signer "kga_${name}.pem" -inkey "kga_${name}_key.pem" \
    -certfile "data/openssl_cms/trustanchors/root_${name}.pem" \
    -keyid -md sha512 -nosmimecap \
    -econtent_type 2.16.840.1.101.2.1.2.78.5
done
```

## Notes

- `-econtent_type 2.16.840.1.101.2.1.2.78.5` sets the `eContentType` to
  `id-ct-KP-aKeyPackage` and forces `SignedData` version 3.
- `-keyid` makes the `SignerIdentifier` a `subjectKeyIdentifier` (SignerInfo version 3),
  as required for KGA responses.
- The generating OpenSSL version is recorded per file below:
  - `signed_data_ecdsa.der`: OpenSSL 3.0.13
