# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""CMP profile definitions.

A profile is a named set of values that vary between CMP specifications
(lwCMP, GPPCMP, etc.). Set the active profile via the Robot keyword
``Set CMP Profile`` or the CLI flag ``--profile``.
"""

from dataclasses import dataclass, fields
from typing import Optional

from robot.api.deco import keyword


@dataclass
class CMPProfile:
    """Parameters that vary between CMP profiles.

    Attributes:
        name: Profile identifier (e.g. ``lwcmp``, ``gppcmp``).
        datatracker_url: IETF datatracker URL for the profile specification,
            or ``None`` if not yet published.
        nonce_size: Exact nonce size in bytes to generate.
        max_nonce_size: Maximum allowed nonce size in bytes. ``None`` means
            nonces must be exactly ``nonce_size`` bytes.
        tx_id_size: Transaction ID size in bytes.
        min_nonce_sec: Minimum nonce security size in bytes. ``None`` means
            no minimum is enforced by the profile.

    """

    name: str
    datatracker_url: Optional[str]
    nonce_size: int
    max_nonce_size: Optional[int]
    tx_id_size: int
    min_nonce_sec: Optional[int]

    @staticmethod
    def _validate_positive(field: str, value: int) -> None:
        """Validate that a profile field is a positive integer."""
        if value <= 0:
            raise ValueError(f"CMPProfile.{field} must be positive, got {value}")

    @staticmethod
    def _validate_optional_positive(field: str, value: Optional[int]) -> None:
        """Validate that a profile field is a positive integer."""
        if value is not None and value <= 0:
            raise ValueError(f"CMPProfile.{field} must be positive or None, got {value}")

    @staticmethod
    def _validate_at_least(field: str, value: int, floor: int) -> None:
        """Validate that a profile field is an integer >= floor."""
        if value < floor:
            raise ValueError(f"CMPProfile.{field} ({value}) must be >= {floor}")

    @staticmethod
    def _validate_optional_at_least(field: str, value: Optional[int], floor: int) -> None:
        """Validate that a profile field is an integer >= floor."""
        if value is not None and value < floor:
            raise ValueError(f"CMPProfile.{field} ({value}) must be >= {floor}")

    def __post_init__(self) -> None:
        """Validate the profile parameters after initialization."""
        if not self.name:
            raise ValueError("CMPProfile.name must be a non-empty string")

        if self.datatracker_url is not None and not isinstance(self.datatracker_url, str):
            raise ValueError("CMPProfile.datatracker_url must be a string or None")

        CMPProfile._validate_positive("nonce_size", self.nonce_size)
        CMPProfile._validate_optional_positive("max_nonce_size", self.max_nonce_size)
        CMPProfile._validate_optional_at_least("max_nonce_size", self.max_nonce_size, self.nonce_size)
        CMPProfile._validate_positive("tx_id_size", self.tx_id_size)
        CMPProfile._validate_optional_positive("min_nonce_sec", self.min_nonce_sec)
        CMPProfile._validate_at_least("nonce_size", self.nonce_size, self.min_nonce_sec or 0)


# --- Predefined profiles ---------------------------------------------------

CMP = CMPProfile(
    name="cmp",
    datatracker_url="https://datatracker.ietf.org/doc/rfc9810/",
    nonce_size=16,
    max_nonce_size=None,
    tx_id_size=16,
    min_nonce_sec=16,
)

LWCMP = CMPProfile(
    name="lwcmp",
    datatracker_url="https://datatracker.ietf.org/doc/rfc9483/",
    nonce_size=16,
    max_nonce_size=None,
    tx_id_size=16,
    min_nonce_sec=None,
)

GPPCMP = CMPProfile(
    name="gppcmp",
    datatracker_url=None,
    nonce_size=4096,
    max_nonce_size=None,
    tx_id_size=16,
    min_nonce_sec=16,
)

PROFILES = {
    "cmp": CMP,
    "lwcmp": LWCMP,
    "gppcmp": GPPCMP,
}

# --- Active profile ---------------------------------------------------------

_active_profile: CMPProfile = CMP


@keyword("Set CMP Profile")
def set_cmp_profile(name: str) -> CMPProfile:
    """Set the active CMP profile by name.

    Exposed as the Robot keyword ``Set CMP Profile``.

    Args:
        name: Profile name. Must exist in PROFILES.

    Returns:
        The activated CMPProfile instance.

    Raises:
        ValueError: If the profile name is unknown.

    """
    global _active_profile
    if name not in PROFILES:
        raise ValueError(f"Unknown profile '{name}'. Available: {sorted(PROFILES)}")
    _active_profile = PROFILES[name]
    return _active_profile

def get_active_profile() -> CMPProfile:
    """Return the currently active CMPProfile."""
    return _active_profile


def get_profile_value(key: str):
    """Read a value from the active CMP profile by field name.

    Args:
        key: CMPProfile field name (e.g. ``nonce_size``, ``tx_id_size``).

    Returns:
        The field value.

    Raises:
        KeyError: If the field name does not exist on CMPProfile.

    """
    if not hasattr(_active_profile, key):
        valid = [f.name for f in fields(CMPProfile)]
        raise KeyError(f"Unknown profile key '{key}'. Available: {valid}")
    return getattr(_active_profile, key)
