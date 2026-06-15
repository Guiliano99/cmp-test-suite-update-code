"""Tests for MockCA remote-attestation structure wrappers."""

import unittest

from resources.remote_att_utils import attest_nonce_freshness_structures as mockca_freshness
from resources.remote_att_utils import attest_structures as mockca_tpm
from resources.remote_att_utils import csr_attest_structures as mockca_csr

from libattest.formats import csrattest as libattest_csr
from libattest.formats import tpm as libattest_tpm


class LibattestRemoteAttUtilsWrappersTest(unittest.TestCase):
    """Ensure MockCA keeps stable imports while using libattest structures."""

    def test_csr_attestation_structures_are_imported_from_libattest(self) -> None:
        self.assertIs(mockca_csr.AttestationBundle, libattest_csr.AttestationBundle)
        self.assertIs(mockca_csr.AttestationStatement, libattest_csr.AttestationStatement)
        self.assertIs(mockca_csr.AttestationSequence, libattest_csr.AttestationSequence)
        self.assertIs(mockca_csr.AttestCertSequence, libattest_csr.AttestCertSequence)
        self.assertEqual(mockca_csr.id_aa_attestation, libattest_csr.id_aa_attestation)

    def test_freshness_structures_are_imported_from_libattest(self) -> None:
        self.assertIs(mockca_freshness.NonceRequestASN1, libattest_csr.NonceRequestASN1)
        self.assertIs(mockca_freshness.NonceResponseASN1, libattest_csr.NonceResponseASN1)

    def test_tpm_structures_are_imported_from_libattest(self) -> None:
        self.assertIs(mockca_tpm.TcgAttestCertify, libattest_tpm.TcgAttestCertify)
        self.assertEqual(mockca_tpm.id_tcg_attest_certify, libattest_tpm.id_tcg_attest_certify)


if __name__ == "__main__":
    unittest.main()
