# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler

from pq_logic.hybrid_sig.chameleon_logic import build_paired_csr
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import is_bit_set
from resources.cmputils import build_p10cr_from_csr, get_cmp_message_type, get_pkistatusinfo
from resources.exceptions import BadAsn1Data
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import build_pkimessage, de_and_encode_pkimessage


class TestMockCAErrorPvno(unittest.TestCase):
    """Check the `pvno` of the error messages of the Mock CA.

    RFC 9810 Section 7: "If a server receives a message with a version that it supports, then
    the version of the response message MUST be the same as the received version."

    The Mock CA supports the versions 2 and 3.
    """

    @classmethod
    def setUpClass(cls):
        cls.ca_handler = CAHandler()

    def _check_is_error_with_pvno(self, response: PKIMessageTMP, pvno: int) -> None:
        """Check that the response is an error message with the expected `pvno`.

        :param response: The response of the Mock CA.
        :param pvno: The expected protocol version number.
        """
        response = de_and_encode_pkimessage(response)
        self.assertEqual(get_cmp_message_type(response), "error")
        self.assertEqual(int(response["header"]["pvno"]), pvno)

    def test_supported_version_is_returned(self):
        """
        GIVEN an unprotected request with a supported `pvno`.
        WHEN the Mock CA rejects the request,
        THEN the error message has the `pvno` of the request.
        """
        for pvno in (2, 3):
            with self.subTest(pvno=pvno):
                request = build_pkimessage(pvno=pvno)
                response = self.ca_handler.process_normal_request(request)
                self._check_is_error_with_pvno(response, pvno)

    def test_higher_version_gets_highest_supported_version(self):
        """
        GIVEN a request with a `pvno`, which is higher than the highest supported version.
        WHEN the Mock CA rejects the request,
        THEN the error message has the `pvno` 3.

        RFC 9810 Section 7: "If the received version is higher than the highest supported version, then
        the version in the error message MUST be the highest version the server supports".
        """
        for pvno in (4, 2**64):
            with self.subTest(pvno=pvno):
                request = build_pkimessage(pvno=pvno)
                response = self.ca_handler.process_normal_request(request)
                self._check_is_error_with_pvno(response, 3)

    def test_lower_version_gets_lowest_supported_version(self):
        """
        GIVEN a request with a `pvno`, which is lower than the lowest supported version.
        WHEN the Mock CA rejects the request,
        THEN the error message has the `pvno` 2.

        RFC 9810 Section 7: "if the received version is lower than the lowest supported version, then
        the version in the error message MUST be the lowest version the server supports."
        """
        for pvno in (-1, 0, 1):
            with self.subTest(pvno=pvno):
                request = build_pkimessage(pvno=pvno)
                response = self.ca_handler.process_normal_request(request)
                self._check_is_error_with_pvno(response, 2)

    def test_chameleon_error_belongs_to_the_request(self):
        """
        GIVEN a chameleon request with the `pvno` 3 and an invalid alternative POP.
        WHEN the Mock CA rejects the request,
        THEN the error message has the `pvno`, the `transactionID` and the nonce of the request.
        """
        csr = build_paired_csr(
            base_private_key=load_private_key_from_file("data/keys/private-key-ecdsa.pem"),
            delta_private_key=load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem"),
            bad_alt_pop=True,
        )
        request = build_p10cr_from_csr(csr, pvno=3)
        response = self.ca_handler.process_chameleon(request)
        self._check_is_error_with_pvno(response, 3)
        self.assertTrue(is_bit_set(get_pkistatusinfo(response)["failInfo"], "badPOP"))
        self.assertEqual(
            response["header"]["transactionID"].asOctets(), request["header"]["transactionID"].asOctets()
        )
        self.assertEqual(response["header"]["recipNonce"].asOctets(), request["header"]["senderNonce"].asOctets())

    def test_undecodable_request_gets_default_version(self):
        """
        GIVEN a request, which could not be decoded.
        WHEN the Mock CA builds the error message,
        THEN the error message has the `pvno` 2.
        """
        response = self.ca_handler.build_error_from_exception(BadAsn1Data("Could not decode the request"))
        self._check_is_error_with_pvno(response, 2)


if __name__ == "__main__":
    unittest.main()
