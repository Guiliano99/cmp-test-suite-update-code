# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Type aliases to enhance code readability, maintainability, and type safety.

Type aliases are used to create descriptive names for commonly used types, making the codebase
easier to understand and work with.
"""

from typing import List, Optional, Sequence, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from keyutils_py.types import (
    ECDHPrivateKey,
    ECDHPublicKey,
    HybridSigPrivateKey,
    KEMPrivateKey,
    KEMPublicKey,
    PQSignaturePrivateKey,
    TradSignKey,
)
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402, rfc9480, rfc9629

from pq_logic.hybrid_structures import DeltaCertificateDescriptor, DeltaCertificateRequestValue
from resources.asn1_structures import CertResponseTMP, PKIMessageTMP

# The key types (`PrivateKey`, `SignKey`, `ECDHPrivateKey`, ...) are defined in `keyutils_py.types`,
# which is the only place to import them from. This module only holds the CMP specific aliases.

# These `cryptography` keys can be used to sign a certificate.
# For signature protection, a certificate is required in the
# first position of the `pyasn1 rfc9480.PKIMessage` `extraCerts` field.
# To ensure the correct keys are used, this type is introduced.
PrivSignCertKey = Union[TradSignKey, PQSignaturePrivateKey, HybridSigPrivateKey]

# At different stages of RobotFramework tests we deal with
# certificates in forms, e.g., pyasn1 structures, or filepaths. This type
# is used in functions that can accept either of these formats
# and will transform them internally, as required.
CertObjOrPath = Union[rfc9480.CMPCertificate, str]


# The `KGAKeyTypes` includes all private key types supported
# for operations in the Key Generation Authority (KGA) logic.
# This type ensures that only compatible private keys are used
# for key exchange and key encipherment.
EnvDataPrivateKey = Union[RSAPrivateKey, ECDHPrivateKey, KEMPrivateKey]

EnvDataPublicKey = Union[RSAPublicKey, ECDHPublicKey, KEMPublicKey]
CertOrCerts = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]

# Often can either an utf-8 string or a hey string or a bytes object be used,
# to parse a shared secret or a key.
OptSecret = Optional[Union[str, bytes]]

# All recipient info types supported by the CMP protocol.
# This type is used to ensure that all recipient info types are handled correctly
# in CMP-related operations.
RecipInfo = Union[
    rfc5652.RecipientInfo,
    rfc5652.KeyTransRecipientInfo,
    rfc5652.KeyAgreeRecipientInfo,
    rfc5652.PasswordRecipientInfo,
    rfc9629.KEMRecipientInfo,
    rfc5652.OtherRecipientInfo,
]

ControlsType = Union[
    rfc9480.Controls,
    Sequence[rfc9480.AttributeTypeAndValue],
    rfc9480.AttributeTypeAndValue,
]

ExtensionsParseType = Union[
    rfc9480.Extensions,
    Sequence[rfc5280.Extension],
    rfc5280.Extension,
]
CAResponse = Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]
CACertResponse = Tuple[CertResponseTMP, rfc9480.CMPCertificate]
CACertResponses = Tuple[List[CertResponseTMP], List[rfc9480.CMPCertificate]]

# The `CRLFullNameType` includes all types supported for CRL full names.
# This type ensures that only compatible types are used in CRL-related preparation functions.
CRLFullNameType = Union[
    str,
    rfc9480.GeneralName,
    Sequence[rfc9480.GeneralName],
]

CertRequestType = Union[
    rfc9480.CertTemplate,
    rfc6402.CertificationRequest,
    DeltaCertificateRequestValue,
]

CertRelatedType = Union[
    rfc9480.CMPCertificate,
    CertRequestType,
    DeltaCertificateDescriptor,
]

ExtensionsType = Union[rfc5280.Extensions, Sequence[rfc5280.Extension], List[rfc9480.Extensions]]
GeneralNamesType = Union[str, rfc9480.GeneralName, Sequence[rfc9480.GeneralName], rfc9480.GeneralNames, rfc9480.Name]
