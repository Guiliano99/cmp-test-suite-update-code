# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc9481
from resources.cmputils import prepare_popo, prepare_sig_popo_structure
from resources.keyutils import generate_key, load_private_key_from_file


class TestPreparePOPO(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = load_private_key_from_file("./data/keys/private-key-rsa.pem", password=None)
        cls.signature = bytes.fromhex("AA" * 32)

    def test_prepare_pop_valid(self):
        """
        GIVEN a signature and private key.
        WHEN prepare_pop is called with valid PoP (Proof of Possession).
        THEN it should return a valid ProofOfPossession structure.
        """
        popo = prepare_popo(signature=self.signature, signing_key=self.private_key)

        encoded_popo = encoder.encode(popo)

        decoded_popo, rest = decoder.decode(encoded_popo, asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"", "Decoding did not consume the entire input")
        self.assertTrue(decoded_popo["signature"].isValue, "Signature field is missing or empty")
        self.assertEqual(decoded_popo["signature"]["signature"], univ.BitString().fromOctetString(self.signature))

    def test_prepare_pop_with_ra_verified(self):
        """
        GIVEN a signature and ra_verified flag set to True.
        WHEN prepare_pop is called with ra_verified set to True.
        THEN it should return a ProofOfPossession structure with the raVerified field set.
        """
        popo = prepare_popo(signature=self.signature, signing_key=self.private_key, ra_verified=True)
        encoded_popo = encoder.encode(popo)
        decoded_popo, rest = decoder.decode(encoded_popo, asn1Spec=rfc4211.ProofOfPossession())

        self.assertEqual(rest, b"", "Decoding did not consume the entire input")
        self.assertTrue(decoded_popo["raVerified"].isValue, "RA verification field is missing or empty")
        self.assertEqual(
            decoded_popo["raVerified"],
            univ.Null("").subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        )

    def test_prepare_pop_invalid_without_private_key_or_alg_oid(self):
        """
        GIVEN a signature without a private key or algorithm OID.
        WHEN prepare_pop is called without private_key and alg_oid.
        THEN it should raise a ValueError.
        """
        with self.assertRaises(ValueError):
            prepare_popo(signature=self.signature, signing_key=None, alg_oid=None)

    def test_prepare_sig_popo_structure_with_oid(self):
        """
        GIVEN a signature algorithm OID instead of an `AlgorithmIdentifier`.
        WHEN prepare_sig_popo_structure is called with that OID, an Ed25519 key and a fixed signature.
        THEN the encoded POPO decodes without remainder, its algorithm is the OID and the
        parameters are absent, as RFC 8410 Section 6 requires for Ed25519.
        """
        ed_key = generate_key("ed25519")
        popo = prepare_sig_popo_structure(alg_id=rfc9481.id_Ed25519, signing_key=ed_key, signature=self.signature)
        decoded, rest = decoder.decode(encoder.encode(popo), asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")
        alg_id = decoded["signature"]["algorithmIdentifier"]
        self.assertEqual(alg_id["algorithm"], rfc9481.id_Ed25519)
        self.assertFalse(alg_id["parameters"].isValue)


if __name__ == "__main__":
    unittest.main()
