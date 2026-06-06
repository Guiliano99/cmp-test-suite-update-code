<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# EST Reference Materials

Specifications and supporting standards relevant to testing the **Enrollment
over Secure Transport (EST)** protocol in this folder.

## Table of Contents

- [Core EST Specifications](#core-est-specifications)
- [Foundational Standards EST Builds On](#foundational-standards-est-builds-on)
- [Transport / Encoding](#transport--encoding)
- [Relationship To CMP In This Suite](#relationship-to-cmp-in-this-suite)

---

## Core EST Specifications

- [RFC 7030 — Enrollment over Secure Transport](https://www.rfc-editor.org/rfc/rfc7030)
  — the base EST protocol. Key sections used by the tests:
  - **3.2.2** — well-known URI (`/.well-known/est`), operation paths, optional label
  - **3.2.3** — HTTP layer and headers
  - **3.2.4** — content types per operation
  - **4.1** — distribution of CA certificates (`/cacerts`)
  - **4.2** — client certificate request functions (`/simpleenroll`, `/simplereenroll`)
  - **4.3** — full CMC (`/fullcmc`)
  - **4.4** — server-side key generation (`/serverkeygen`)
  - **4.5** — CSR attributes (`/csrattrs`)
- [RFC 8951 — Clarification of Enrollment over Secure Transport (EST): Transfer Encodings and ASN.1](https://www.rfc-editor.org/rfc/rfc8951)
  — clarifies base64 transfer encoding (`Content-Transfer-Encoding: base64`) and ASN.1 usage.
- [RFC 8295 — EST (Enrollment over Secure Transport) Extensions](https://www.rfc-editor.org/rfc/rfc8295)
  — additional EST operations and package formats.
- [RFC 7894 — Alternative Challenge Password Attributes for Enrollment over Secure Transport](https://www.rfc-editor.org/rfc/rfc7894)
  — `revocationChallenge` / `estIdentityLinking` CSR attributes.

## Foundational Standards EST Builds On

- [RFC 5272 — Certificate Management over CMS (CMC)](https://datatracker.ietf.org/doc/rfc5272/)
  — Simple PKI Request/Response; the "certs-only" CMS bundle returned by `/cacerts` and enrollment.
- [RFC 5652 — Cryptographic Message Syntax (CMS)](https://datatracker.ietf.org/doc/rfc5652/)
  — `ContentInfo` / `SignedData` carrying the certificates.
- [RFC 2986 — PKCS #10: Certification Request Syntax](https://datatracker.ietf.org/doc/rfc2986/)
  — the `CertificationRequest` (CSR) submitted to `/simpleenroll`.
- [RFC 2985 — PKCS #9: Selected Object Classes and Attribute Types](https://datatracker.ietf.org/doc/rfc2985/)
  — `challengePassword` and related CSR attributes (context for RFC 7894).
- [RFC 5280 — X.509 PKI Certificate and CRL Profile](https://datatracker.ietf.org/doc/rfc5280/)
  — certificate profile of the issued/CA certificates.

## Transport / Encoding

- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/rfc8446/)
  and [RFC 5246 — TLS 1.2](https://datatracker.ietf.org/doc/rfc5246/) — EST mandates TLS (RFC 7030 Section 3.3).
- [RFC 7468 — Textual Encodings of PKIX, PKCS, and CMS Structures](https://datatracker.ietf.org/doc/rfc7468/)
  — PEM/base64 conventions.
- [RFC 5785 — Defining Well-Known Uniform Resource Identifiers (URIs)](https://datatracker.ietf.org/doc/rfc5785/)
  — basis for the `/.well-known/est` prefix.

## Relationship To CMP In This Suite

EST and CMP solve overlapping problems (certificate enrollment), and the
top-level suite documents CMP extensively (see [../REFERENCES.md](../REFERENCES.md)).
EST is HTTP/TLS-native and carries PKCS#10 + CMS, whereas CMP defines its own
`PKIMessage` envelope. The `/cacerts` operation here is the EST analogue of the
CMP `get_ca_certs` general message exercised in
[`../tests/support_messages.robot`](../tests/support_messages.robot).
