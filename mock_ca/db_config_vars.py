# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Dataclasses for configuration variables used by the MockCA."""

from abc import ABC
from dataclasses import asdict, dataclass, field, fields
from typing import List, Optional, Union

from resources.data_objects import KARICertsAndKeys
from resources.exceptions import RemoteAttestationError
from resources.typingutils import SignKey


@dataclass
class ConfigVal(ABC):
    """Base class for configuration values."""

    def to_dict(self) -> dict:
        """Convert the configuration to a dictionary."""
        out = {}
        for x in fields(self):
            out[x.name] = getattr(self, x.name)
        return out


@dataclass
class CertConfConfigVars(ConfigVal):
    """Configuration variables for the certificate confirmation handler.

    Attributes
    ----------
        enforce_same_alg: If the same `MAC` algorithm should be enforced. Defaults to `True`.
        must_be_protected: If the certificate confirmation message must be protected. Defaults to `True`.
        allow_auto_ed: If automatic hash algorithm selection is allowed, for EdDSA. Defaults to `True`.
        must_be_fresh_nonce: If a fresh `nonce` must be used, for the `certConf` message. Defaults to `True`.

    """

    enforce_same_alg: bool = True
    must_be_protected: bool = True
    allow_auto_ed: bool = True
    must_be_fresh_nonce: bool = True

    def to_dict(self) -> dict:
        """Convert the configuration variables to a dictionary."""
        return {
            "enforce_same_alg": self.enforce_same_alg,
            "must_be_protected": self.must_be_protected,
            "allow_auto_ed": self.allow_auto_ed,
            "must_be_fresh_nonce": self.must_be_fresh_nonce,
        }


@dataclass
class VerifyState(ConfigVal):
    """A simple class to store the verification state.

    Attributes:
        allow_only_authorized_certs: If only authorized certificates are allowed. Defaults to `False`.
        use_openssl: If OpenSSL should be used for verification. Defaults to `False`.
        algorithms: The algorithms to use. Defaults to "ecc+,rsa, pq, hybrid".
        curves: The curves to use. Defaults to "all".
        hash_alg: The hash algorithm to use. Defaults to "all".

    """

    allow_only_authorized_certs: bool = False
    use_openssl: bool = False
    algorithms: str = "ecc+,rsa, pq, hybrid"
    curves: str = "all"
    hash_alg: str = "all"


@dataclass
class TrustConfig(ConfigVal):
    """Configuration for the trust store.

    Attributes:
        mock_ca_trusted_dir: The directory containing the trusted CA certificates.
        Defaults to "data/mock_ca/trustanchors".
        trusted_ras_dir: The directory containing the trusted RA certificates, for `raVerified`
        and nested requests. Defaults to `None`.
        trusted_cas_dir: The directory containing the trusted CA certificates for
        Cross-Certification. Defaults to `None`.

    """

    mock_ca_trusted_dir: str = "data/mock_ca/trustanchors"
    trusted_ras_dir: Optional[str] = None
    trusted_cas_dir: Optional[str] = None


@dataclass
class ProtectionHandlerConfig(ConfigVal):
    """Configuration for the ProtectionHandler.

    Attributes:
        use_openssl: Whether to use OpenSSL for verification. Defaults to `True`.
        prot_alt_key: The alternative signing key to use for hybrid signatures. Defaults to `None`.
        include_alt_sig_key: Whether to include the alternative signing key in the PKIMessage. Defaults to `True`.
        kari_certs: The KARI certificates and keys to use for `DHBasedMac` protection. Defaults to `None`.
        Defaults to "data/mock_ca/trustanchors".
        enforce_lwcmp: Whether to enforce the use of LwCMP algorithm profile RFC9483. Defaults to `False`.

    """

    pre_shared_secret: Union[bytes, str] = b"SiemensIT"
    def_mac_alg: str = "password_based_mac"
    use_openssl: bool = True
    prot_alt_key: Optional[SignKey] = None
    include_alt_sig_key: bool = True
    kari_certs: Optional[KARICertsAndKeys] = None
    enforce_lwcmp: bool = False
    trusted_config: TrustConfig = field(default_factory=TrustConfig)

    def __post_init__(self):
        """Post-initialization to ensure the pre_shared_secret is in bytes."""
        if isinstance(self.trusted_config, dict):
            # If a dictionary is passed, convert it to TrustConfig
            self.trusted_config = TrustConfig(**self.trusted_config)

    @property
    def mock_ca_trusted_dir(self) -> str:
        """Get the directory containing the trusted CA certificates."""
        return self.trusted_config.mock_ca_trusted_dir

    @property
    def trusted_ras_dir(self) -> Optional[str]:
        """Get the directory containing the trusted RA certificates."""
        return self.trusted_config.trusted_ras_dir

    @property
    def trusted_cas_dir(self) -> Optional[str]:
        """Get the directory containing the trusted CA certificates for Cross-Certification."""
        return self.trusted_config.trusted_cas_dir

    def to_dict(self) -> dict:
        """Convert the configuration to a dictionary."""
        return {
            "pre_shared_secret": self.pre_shared_secret,
            "def_mac_alg": self.def_mac_alg,
            "use_openssl": self.use_openssl,
            "prot_alt_key": self.prot_alt_key,
            "include_alt_sig_key": self.include_alt_sig_key,
            "kari_certs": self.kari_certs,
            "enforce_lwcmp": self.enforce_lwcmp,
            **self.trusted_config.to_dict(),
        }


@dataclass
class VerifierEntry(ConfigVal):
    """An entry for a known verifier.

    Attributes
    ----------
        name: The name of the verifier.
        location: The location of the verifier.

    """

    name: str
    location: str

    def to_dict(self) -> dict:
        """Convert the configuration to a dictionary."""
        return {
            "name": self.name,
            "location": self.location,
        }


@dataclass
class AttestationNonceConfig(ConfigVal):
    """Configuration for the Attestation Nonce handling.

    Attributes
    ----------
        `min_nonce_length`: The minimum length of the nonce. Defaults to `None`.
        `verifiers`: The list of known verifiers for the remote attestation. Defaults to `None`.
        `allow_self_generated_nonce`: If self-generated nonces are allowed. Defaults to `True`.
        `fetch_timeout`: The timeout for fetching the nonce from the verifier. Defaults to `10 seconds`.
        `expiration_time`: The expiration time of the nonce in seconds. Defaults to `50 seconds`.

    """

    min_nonce_length: Optional[int] = None
    allow_self_generated_nonce: bool = True
    fetch_timeout: int = 10
    expiration_time: int = 50

    def to_dict(self) -> dict:
        """Convert the configuration to a dictionary."""
        return asdict(self)


@dataclass
class RemoteAttestationIssuingConfig(ConfigVal):
    """Configuration for the Remote Attestation Issuing Handler."""

    verify_cert_chain: bool = True
    trusted_config: TrustConfig = field(default_factory=TrustConfig)

    @property
    def mock_ca_trusted_dir(self) -> str:
        """Get the directory containing the trusted CA certificates."""
        return self.trusted_config.mock_ca_trusted_dir


@dataclass
class RemoteAttestationConfig(ConfigVal):
    """Configuration for the Remote Attestation Handler.

    Attributes:
        - `attestation_nonce_config`: The configuration for the attestation nonce handling.
        - `verifiers`: The list of known verifiers for the remote attestation.

    """

    attestation_nonce_config: AttestationNonceConfig = field(default_factory=AttestationNonceConfig)
    attention_config: Optional[dict] = None
    verifiers: Optional[List[VerifierEntry]] = None

    def __post_init__(self):
        """Post-initialization to convert the verifiers to VerifierEntry objects."""
        if self.verifiers is not None:
            for i, v in enumerate(self.verifiers):
                if isinstance(v, dict):
                    self.verifiers[i] = VerifierEntry(**v)

    def contains_verifier(self, name: str) -> bool:
        """Check if the verifier is known.

        :param name: The name of the verifier.
        :return: True if the verifier is known, False otherwise.
        """
        if self.verifiers is None:
            return False

        for verifier in self.verifiers:
            if verifier.name == name:
                return True
        return False

    def get_verifier(self, name: str) -> Optional[VerifierEntry]:
        """Get the verifier with the given name.

        :param name: The name of the verifier.
        """
        if not self.verifiers:
            raise RemoteAttestationError("No remote attestation verifiers configured.")

        for verifier in self.verifiers:
            if verifier.name == name:
                return verifier

        return None
