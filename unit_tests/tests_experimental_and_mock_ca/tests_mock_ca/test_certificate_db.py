# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509 import ocsp
from mock_ca.mock_fun import CertDBEntry, CertificateDB, CertStateEnum, RevokedEntry
from mock_ca.operation_dbs import load_ca_cert_and_key

from resources.asn1utils import encode_to_der
from resources.certutils import cert_in_list, create_ocsp_request, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.oid_mapping import compute_hash
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import compare_pyasn1_objects


class TestCertificateDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example_cert = parse_certificate(load_and_decode_pem_file("./data/unittest/ca2_cert_rsa.pem"))
        cls.example_key = load_private_key_from_file(
            "./data/keys/private-key-rsa.pem",
            password=None,
        )
        cls.example_cert2 = parse_certificate(load_and_decode_pem_file("./data/unittest/ca1_cert_ecdsa.pem"))

        cls.cert1_digest = compute_hash("sha1", encode_to_der(cls.example_cert))
        cls.updated_cert_digest = compute_hash("sha1", encode_to_der(cls.example_cert2))
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()

    def test_add_cert(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is added to the database.
        THEN it should be retrievable from the database.
        """
        # Assuming CertificateDB has an add_cert method
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)

        # Check if the certificate is in the database
        self.assertTrue(cert_in_list(self.example_cert, db.issued_certs))
        self.assertIsNone(db.get_cert(self.example_cert2))
        self.assertIsNotNone(db.get_cert(self.example_cert))
        cert_entry: CertDBEntry = db.get_cert(self.example_cert)
        self.assertEqual(cert_entry.cert_state, CertStateEnum.CONFIRMED)
        self.assertTrue(compare_pyasn1_objects(self.example_cert, cert_entry.cert))
        self.assertEqual(self.cert1_digest, cert_entry.cert_digest)

    def test_change_cert_state_revoked(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate state is changed to revoked.
        THEN it should be reflected in the database.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)

        # Change the state to revoked
        db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.REVOKED)

        # Check if the state is updated
        cert_entry: CertDBEntry = db.get_cert(self.example_cert)
        self.assertEqual(cert_entry.cert_state, CertStateEnum.REVOKED)

    def test_change_cert_state_revoked_to_confirmed(self):
        """
        GIVEN a revoked certificate and a CertificateDB instance.
        WHEN the certificate state is changed to confirmed.
        THEN it should raise a ValueError.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.REVOKED)

        with self.assertRaises(ValueError):
            db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.CONFIRMED)

    def test_not_confirmed_updated_cert(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is added to the database with a state other than CONFIRMED.
        THEN it should not be retrievable from the database.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            updated_cert=self.example_cert2,
        )

        self.assertIsNotNone(db.get_cert(self.example_cert))
        self.assertIsNone(db.get_cert(self.example_cert2))

        cert_entry: CertDBEntry = db.get_cert(self.example_cert)
        self.assertEqual(cert_entry.cert_state, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED)
        self.assertTrue(compare_pyasn1_objects(self.example_cert, cert_entry.cert))
        self.assertEqual(self.cert1_digest, cert_entry.cert_digest)
        self.assertEqual(self.updated_cert_digest, cert_entry.update_cert_digest)

    def test_update_cert(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is updated in the database.
        THEN it should be retrievable and the state should be correct.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            updated_cert=self.example_cert2,
        )

        # Check if the updated certificate is in the database
        self.assertIsNone(db.get_cert(self.example_cert2))
        with self.assertRaises(ValueError):
            db.change_cert_state(
                cert=self.example_cert,
                new_state=CertStateEnum.CONFIRMED,
                updated_cert=self.example_cert2,
            )

    def test_confirm_not_update_then_updated(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is added to the database with a state other than CONFIRMED.
        THEN it should not be retrievable from the database.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            updated_cert=self.example_cert2,
        )
        self.assertIsNotNone(db.get_cert(self.example_cert))
        self.assertEqual(db.get_cert(self.example_cert).cert_state, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED)

        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED,
            updated_cert=None,
        )
        self.assertIsNotNone(db.get_cert(self.example_cert))
        self.assertIsNone(db.get_cert(self.example_cert2))

    def test_crl_number_increases(self):
        """
        GIVEN an empty CertificateDB and the Mock CA test root.
        WHEN the current CRL is asked twice.
        THEN the CRL numbers are 1 and 2 (RFC 5280 Section 5.2.3: two CRLs of one scope MUST NOT have the same
        CRL number).
        """
        db = CertificateDB()
        crl_numbers = [
            db.get_current_crl(ca_key=self.ca_key, ca_cert=self.ca_cert)
            .extensions.get_extension_for_class(x509.CRLNumber)
            .value.crl_number
            for _ in range(2)
        ]
        self.assertEqual(crl_numbers, [1, 2])

    def _crl_entry_and_ocsp(self, db: CertificateDB, cert):
        """Return the CRL entry of `cert` in the current CRL of `db` and the OCSP response of `db` for `cert`."""
        crl = db.get_current_crl(ca_key=self.ca_key, ca_cert=self.ca_cert)
        crl_entry = crl.get_revoked_certificate_by_serial_number(int(cert["tbsCertificate"]["serialNumber"]))
        self.assertIsNotNone(crl_entry)
        ocsp_request, _ = create_ocsp_request(cert, self.ca_cert, must_be_present=False)
        ocsp_response = db.get_ocsp_response(request=ocsp_request, sign_key=self.ca_key, ca_cert=self.ca_cert)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(ocsp_response.certificate_status, ocsp.OCSPCertStatus.REVOKED)
        return crl_entry, ocsp_response

    def _revoke(self, db: CertificateDB, reason: str) -> datetime:
        """Add the example certificate as confirmed, revoke it with a fixed date and `reason`, return the date."""
        revoked_date = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.REVOKED,
            revoke_entry=RevokedEntry(reason=reason, cert=self.example_cert, revoked_date=revoked_date),
        )
        return revoked_date

    def test_crl_and_ocsp_use_stored_revocation_date_and_reason(self):
        """
        GIVEN a certificate revoked with the reason `keyCompromise` and a fixed revocation date.
        WHEN the current CRL and an OCSP response for it are built.
        THEN both carry the stored date and the reason `keyCompromise` (RFC 5280 Section 5.1.2.6, RFC 6960
        Section 2.4).
        """
        db = CertificateDB()
        revoked_date = self._revoke(db, reason="keyCompromise")
        crl_entry, ocsp_response = self._crl_entry_and_ocsp(db, self.example_cert)
        self.assertEqual(crl_entry.revocation_date_utc, revoked_date)
        crl_reason = crl_entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        self.assertEqual(crl_reason, x509.ReasonFlags.key_compromise)
        self.assertEqual(ocsp_response.revocation_time_utc, revoked_date)
        self.assertEqual(ocsp_response.revocation_reason, x509.ReasonFlags.key_compromise)

    def test_unspecified_reason_is_absent(self):
        """
        GIVEN a certificate revoked with the reason `unspecified` and a fixed revocation date.
        WHEN the current CRL and an OCSP response for it are built.
        THEN both carry the stored date and no reason (RFC 5280 Section 5.3.1: the reason code SHOULD be absent
        instead of using the unspecified (0) reasonCode value).
        """
        db = CertificateDB()
        revoked_date = self._revoke(db, reason="unspecified")
        crl_entry, ocsp_response = self._crl_entry_and_ocsp(db, self.example_cert)
        self.assertEqual(crl_entry.revocation_date_utc, revoked_date)
        with self.assertRaises(x509.ExtensionNotFound):
            crl_entry.extensions.get_extension_for_class(x509.CRLReason)
        self.assertEqual(ocsp_response.revocation_time_utc, revoked_date)
        self.assertIsNone(ocsp_response.revocation_reason)

    def test_revocation_without_entry_stores_one(self):
        """
        GIVEN a confirmed certificate.
        WHEN its state is changed to revoked without a revoked entry.
        THEN the database stores an entry with the reason `unspecified` and the revocation date, and the CRL lists
        the certificate with that date.
        """
        db = CertificateDB()
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        before = datetime.now(timezone.utc)
        db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.REVOKED)

        revoked_entry = db.get_cert(self.example_cert).revoked_entry
        self.assertIsNotNone(revoked_entry)
        self.assertEqual(revoked_entry.reason, "unspecified")
        self.assertGreaterEqual(revoked_entry.revoked_date, before)
        crl_entry, _ = self._crl_entry_and_ocsp(db, self.example_cert)
        self.assertEqual(crl_entry.revocation_date_utc, revoked_entry.revoked_date.replace(microsecond=0))

    def test_updated_cert_is_superseded_since_its_update_date(self):
        """
        GIVEN a confirmed certificate replaced by a key update.
        WHEN the current CRL and an OCSP response for it are built.
        THEN both list it as revoked with the stored update date and the reason `superseded`.
        """
        db = CertificateDB()
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.UPDATED, updated_cert=self.example_cert2)
        updated_date = db.get_cert(self.example_cert).updated_date

        crl_entry, ocsp_response = self._crl_entry_and_ocsp(db, self.example_cert)
        self.assertEqual(crl_entry.revocation_date_utc, updated_date)
        crl_reason = crl_entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        self.assertEqual(crl_reason, x509.ReasonFlags.superseded)
        self.assertEqual(ocsp_response.revocation_time_utc, updated_date)
        self.assertEqual(ocsp_response.revocation_reason, x509.ReasonFlags.superseded)

    def test_ocsp_for_unknown_serial_is_unknown(self):
        """
        GIVEN a CertificateDB which never stored the certificate.
        WHEN an OCSP response for it is built.
        THEN the response is successful with the status `unknown` and the certificate ID of the request (RFC 6960
        Section 2.2: "unknown" indicates that the responder doesn't know about the certificate being requested).
        """
        db = CertificateDB()
        ocsp_request, _ = create_ocsp_request(self.example_cert, self.ca_cert, must_be_present=False)
        ocsp_response = db.get_ocsp_response(request=ocsp_request, sign_key=self.ca_key, ca_cert=self.ca_cert)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)
        self.assertEqual(ocsp_response.certificate_status, ocsp.OCSPCertStatus.UNKNOWN)
        self.assertEqual(ocsp_response.serial_number, ocsp_request.serial_number)
        self.assertEqual(ocsp_response.issuer_key_hash, ocsp_request.issuer_key_hash)
        self.assertEqual(ocsp_response.issuer_name_hash, ocsp_request.issuer_name_hash)
