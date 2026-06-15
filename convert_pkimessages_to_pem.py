#!/usr/bin/env python3
"""Convert PKIMessage ASN.1 files to PEM format."""

import base64
import sys
import textwrap
from pathlib import Path

# Add the cmp-test-suite directory to the path so we can import from resources
sys.path.insert(0, "/home/debian/IdeaProjects/remote-attest-e2e/tmp/cmp-test-suite")

# Import from pyasn1
from pyasn1.codec.der import decoder, encoder

# Import from pyasn1-alt-modules
from pyasn1_alt_modules import rfc9480

# Import from the local cmp-test-suite resources
# from resources.utils import pyasn1_pkimessage_to_pem

def pyasn1_pkimessage_to_pem(pkimessage):
    """Convert a pyasn1 PKIMessage to PEM format.

    Args:
        pkimessage: A pyasn1 PKIMessage object

    Returns:
        str: PEM formatted PKIMessage
    """
    der_data = encoder.encode(pkimessage)
    b64_encoded = base64.b64encode(der_data).decode("utf-8")
    b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
    pem_data = "-----BEGIN PKI MESSAGE-----\n" + b64_encoded + "\n-----END PKI MESSAGE-----\n"
    return pem_data


def main():
    """Convert PKIMessage ASN.1 files to PEM format."""
    input_dir = Path("/home/debian/IdeaProjects/remote-attest-e2e/out")
    output_dir = Path("/home/debian/IdeaProjects/remote-attest-e2e/out/pem")
    output_dir.mkdir(parents=True, exist_ok=True)

    der_files = sorted(input_dir.glob("*.der"))
    if not der_files:
        raise SystemExit(f"No DER files found in {input_dir}")

    for input_path in der_files:
        print(f"📄 Processing: {input_path.name}")

        # Parse the PKIMessage
        try:
            pkimessage, _ = decoder.decode(
                input_path.read_bytes(),
                asn1Spec=rfc9480.PKIMessage()
            )
            print("   ✓ Successfully parsed PKIMessage")
        except Exception as e:
            print(f"   ✗ Failed to parse PKIMessage: {e}")
            continue

        # Convert to PEM
        try:
            pem_content = pyasn1_pkimessage_to_pem(pkimessage)
            print("   ✓ Converted to PEM")
        except Exception as e:
            print(f"   ✗ Failed to convert to PEM: {e}")
            import traceback
            traceback.print_exc()
            continue

        # Save to file
        output_filename = input_path.with_suffix(".pem").name
        output_path = output_dir / output_filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(pem_content)

        print(f"   ✓ Saved to: {output_path}")
        print()


if __name__ == "__main__":
    main()
