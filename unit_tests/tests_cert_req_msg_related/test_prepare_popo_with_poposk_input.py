import unittest
import os

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc4211

from resources.cmputils import prepare_popo, prepare_poposigningkeyinput
from resources.keyutils import load_private_key_from_file
from resources import prepareutils, convertutils, oid_mapping
from resources.asn1utils import try_decode_pyasn1


class TestPreparePopoWithPoposkInput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_priv = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.rsa_pub = cls.rsa_priv.public_key()

    def test_prepare_popo_with_poposk_input_and_signature(self):
        """GIVEN a POPOSigningKeyInput (with sender) and a signature
        WHEN calling prepare_popo with signing_key, signature and poposk_input
        THEN the returned ProofOfPossession contains the provided poposkInput, signature, and correct algorithmIdentifier.
        """
        sender = "C=DE,ST=Bavaria,L=Munich,CN=Alice Example"
        poposk_input = prepare_poposigningkeyinput(public_key=self.rsa_pub, sender=sender)

        # Provide a dummy signature (the code only embeds it; no verification here)
        signature_bytes = os.urandom(32)
        popo = prepare_popo(
            signature=signature_bytes,
            signing_key=self.rsa_priv,
            poposk_input=poposk_input,
        )

        self.assertIsInstance(popo, rfc4211.ProofOfPossession)
        # Ensure we are in the 'signature' choice.
        self.assertTrue(popo["signature"].isValue)

        self.assertTrue(popo["signature"]["poposkInput"].isValue)
        actual_name = popo["signature"]["poposkInput"]["authInfo"]["sender"]["directoryName"]
        expected_name = prepareutils.prepare_name(sender, 4)
        self.assertEqual(
            encoder.encode(actual_name["rdnSequence"]),
            encoder.encode(expected_name["rdnSequence"]),
        )

        expected_spki = convertutils.subject_public_key_info_from_pubkey(self.rsa_pub)
        self.assertEqual(
            encoder.encode(popo["signature"]["poposkInput"]["publicKey"]),
            encoder.encode(expected_spki),
        )

        # Signature bytes preserved.
        self.assertEqual(popo["signature"]["signature"].asOctets(), signature_bytes)

        # AlgorithmIdentifier derived from key & hash (sha256 default).
        expected_alg_oid = oid_mapping.get_alg_oid_from_key_hash(self.rsa_priv, hash_alg="sha256")
        self.assertEqual(popo["signature"]["algorithmIdentifier"]["algorithm"], expected_alg_oid)

        # Roundtrip DER encode/decode
        der_data = encoder.encode(popo)
        decoded_popo, rest = try_decode_pyasn1(der_data, rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")
        self.assertEqual(encoder.encode(decoded_popo), der_data)


if __name__ == "__main__":
    unittest.main()
