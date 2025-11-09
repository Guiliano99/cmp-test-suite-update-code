import unittest

from resources.asn1utils import encode_to_der
from resources.certbuildutils import prepare_private_key_possession_statement, prepare_issuer_and_serial_number
from resources.prepareutils import prepare_name
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestPreparePrivateKeyPossessionStatement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cert, sign_key = load_ca_cert_and_key()
        cls.signer_cert = cert
        cls.sign_key = sign_key

    def test_prepare_private_key_possession_statement_with_cert(self):
        """
        GIVEN a signer certificate.
        WHEN prepare_private_key_possession_statement is called with include_cert=True,
        THEN the returned statement should include the certificate and issuer information.
        """
        statement = prepare_private_key_possession_statement(signer_cert=self.signer_cert, include_cert=True)
        self.assertIsNotNone(statement)
        self.assertTrue(statement["cert"].isValue)
        self.assertTrue(statement["signer"].isValue)
        self.assertEqual(statement["cert"], self.signer_cert)

    def test_prepare_private_key_possession_statement_without_cert(self):
        """
        GIVEN a signer certificate.
        WHEN prepare_private_key_possession_statement is called with include_cert=False,
        THEN the returned statement should include issuer information but not the certificate.
        """
        statement = prepare_private_key_possession_statement(signer_cert=self.signer_cert, include_cert=False)
        self.assertIsNotNone(statement)
        self.assertFalse(statement["cert"].isValue)
        self.assertTrue(statement["signer"].isValue)

    def test_prepare_private_key_possession_statement_iss_and_serial(self):
        """
        GIVEN a signer certificate and issuer/serial number.
        WHEN prepare_private_key_possession_statement is called with these parameters,
        THEN the returned statement should correctly reflect the provided issuer and serial number.
        """
        name_obj = prepare_name("CN=Test Issuer")
        iss_and_ser = prepare_issuer_and_serial_number(issuer="CN=Test Issuer", serial_number=123456789)
        statement = prepare_private_key_possession_statement(
            signer_cert=self.signer_cert, include_cert=True, issuer_and_serial=iss_and_ser
        )
        issuer = statement["signer"]
        self.assertEqual(encode_to_der(issuer["issuer"]), encode_to_der(name_obj))
        self.assertEqual(123456789, int(issuer["serialNumber"]))
        self.assertTrue(statement["cert"].isValue)
        self.assertEqual(statement["cert"], self.signer_cert)


if __name__ == "__main__":
    unittest.main()
