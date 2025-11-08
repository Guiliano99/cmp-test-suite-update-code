import unittest

from pyasn1.codec.der import encoder

from resources import cmputils, prepareutils, convertutils
from resources.keyutils import load_private_key_from_file
from resources.asn1utils import try_decode_pyasn1
from pyasn1_alt_modules import rfc4211
from resources import prepare_alg_ids
import os


class TestPreparePopoSigningKeyInput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_priv = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.rsa_pub = cls.rsa_priv.public_key()

    def test_prepare_poposigningkeyinput_sets_sender_and_public_key(self):
        """
        GIVEN a valid sender DN string and RSA public key.
        WHEN preparing the POPOSigningKeyInput,
        THEN the resulting structure has the correct sender and public key and decodes cleanly.
        """
        sender = "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann"
        popo_ski = cmputils.prepare_poposigningkeyinput(public_key=self.rsa_pub, sender=sender)
        self.assertIsInstance(popo_ski, rfc4211.POPOSigningKeyInput)

        self.assertEqual(popo_ski["authInfo"].getName(), "sender")
        self.assertEqual(popo_ski["authInfo"]["sender"].getName(), "directoryName")

        expected_name = prepareutils.prepare_name(sender, 4)
        actual_name = popo_ski["authInfo"]["sender"]["directoryName"]

        self.assertEqual(
            encoder.encode(actual_name["rdnSequence"]),
            encoder.encode(expected_name["rdnSequence"]),
        )

        expected_spki = convertutils.subject_public_key_info_from_pubkey(self.rsa_pub)
        self.assertEqual(
            encoder.encode(popo_ski["publicKey"]),
            encoder.encode(expected_spki),
        )

        der_data = encoder.encode(popo_ski)
        decoded_popo_ski, rest = try_decode_pyasn1(der_data, rfc4211.POPOSigningKeyInput())
        self.assertEqual(rest, b"")
        self.assertEqual(encoder.encode(decoded_popo_ski), der_data)

    def test_prepare_poposigningkeyinput_pkmac_without_sender(self):
        """
        GIVEN a public key and PKMAC algorithm and value but no sender
        WHEN preparing the POPOSigningKeyInput,
        THEN authInfo contains a populated publicKeyMAC and publicKey matches the provided key.
        """
        alg_id = prepare_alg_ids.prepare_alg_id("hmac-sha256")
        mac_bytes = os.urandom(10)
        popo_ski = cmputils.prepare_poposigningkeyinput(public_key=self.rsa_pub,
                                                        pkmac_value_alg_id=alg_id,
                                                        pkmac_value=mac_bytes)

        self.assertIsInstance(popo_ski, rfc4211.POPOSigningKeyInput)
        self.assertTrue(popo_ski["authInfo"]["publicKeyMAC"].isValue)
        self.assertEqual(popo_ski["authInfo"].getName(), "publicKeyMAC")
        pkmac = popo_ski["authInfo"]["publicKeyMAC"]
        self.assertEqual(pkmac["algId"]["algorithm"], alg_id["algorithm"])
        self.assertEqual(pkmac["value"].asOctets(), mac_bytes)
        expected_spki = convertutils.subject_public_key_info_from_pubkey(self.rsa_pub)
        self.assertEqual(encoder.encode(popo_ski["publicKey"]), encoder.encode(expected_spki))
        # Round-trip DER encode/decode
        der_data = encoder.encode(popo_ski)
        decoded, rest = try_decode_pyasn1(der_data, rfc4211.POPOSigningKeyInput())
        self.assertEqual(rest, b"")
        self.assertEqual(encoder.encode(decoded), der_data)

if __name__ == "__main__":
    unittest.main()