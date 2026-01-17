# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey

from pq_logic.tmp_oids import COMPOSITE_KEM_VERSION
from resources.keyutils import generate_key


class CompositeKEMKEMCombinerTest(unittest.TestCase):
    """Test the Composite KEM 11 KEM combiner."""

    def test_kem_combiner_example1(self):
        """Example of id-MLKEM768-ECDH-P256-SHA3-256 Combiner function output."""
        # Inputs
        mlkemSS = "7a87233aa6cfacb3f28776785ee1c3ae0175d502ec6a6ef5f12ae426e1b163ef"

        tradSS = "ac00870310b72b5a1820e787ff9d553b05275bf70f3ffa9b8bb821fc9964bb89"
        tradCT = (
            "04d2d4e8a247899f779b6233efabe17d328a0fb3772e5e37eae3405dec1909e3"
            "1984c3ec4cfd462d76d84d178ea104a38122b4f5942ba4a95a62e78c689388158d"
        )
        tradPK = (
            "04f080fa8049e82f6a247555cdf04b927d65d9502673ce87c299344ababb87de8"
            "37a22f3704f471bffc04d66807ffccbbf3fde99e12afe3c5a41e05f80f9236aa9"
        )

        # Outputs
        # ss = SHA3-256(Combined KDF Input)
        ss_expected = "e8a3638eff395201ae3577199e0655c636974e3d9b8746e8ae4511e84f7158d8"

        pq_key = generate_key("ml-kem-768")
        trad_key = generate_key("ecdh", curve="secp256r1")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual(f"composite-kem-{COMPOSITE_KEM_VERSION}-ml-kem-768-ecdh-secp256r1", comp_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.59", str(comp_key.get_oid()))

        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual(f"composite-kem-{COMPOSITE_KEM_VERSION}-ml-kem-768-ecdh-secp256r1", comp_private_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.59", str(comp_private_key.get_oid()))

        ss = comp_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
        )
        self.assertEqual(ss_expected, ss.hex(), "id-MLKEM768-ECDH-P256 Combiner output does not match expected value.")

        ss2 = comp_private_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
        )
        self.assertEqual(ss_expected, ss2.hex(), "Composite KEM combiner output does not match expected value from private key.")

    def test_kem_combiner_example2(self):
        """Example of id-MLKEM768-X25519-SHA3-256 Combiner function output."""
        # Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.
        # Inputs
        mlkemSS = "3553c8859d5013fa95acdaf2e3098f48c513eec4877316d8b118e20848ffe686"
        tradSS = "8cea86ce190015374dc62e392f62873e879f4b91b4e14833bbc90a3861ec8015"
        tradCT = "df1cd647a0794c5aff520844148660491922d6b8172e7f93faf722632171b70d"
        tradPK = "8d21e8c462970d8b8600480f8587277393f113a4e2297286bde54b65aa334311"

        trad_key = generate_key("x25519")
        pq_key = generate_key("ml-kem-768")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual(f"composite-kem-{COMPOSITE_KEM_VERSION}-ml-kem-768-x25519", comp_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.58", str(comp_key.get_oid()))
        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-12-ml-kem-768-x25519", comp_private_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.58", str(comp_private_key.get_oid()))

        # Outputs
        # ss = SHA3-256(Combined KDF Input)
        ss_expected = "491538ed1a0a9bf9bd5622a25e1f8139209f2336dab28a22b61b43523cf7fecc"
        ss = comp_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
        )
        self.assertEqual(
            ss_expected, ss.hex(), "id-MLKEM768-X25519-SHA3-256 Combiner function output does not match expected value."
        )
        ss2 = comp_private_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
        )
        self.assertEqual(
            ss_expected,
            ss2.hex(),
            "id-MLKEM768-X25519-SHA3-256 Combiner function output does not match expected value from private key.",
        )

    def test_kem_combiner_example3(self):
        """Example of id-MLKEM1024-ECDH-P384-SHA3-256 Combiner function output."""
        # Inputs
        mlkemSS = "4ffb4e09862a6b2de28a94f1c45c0ff156427f7889c8cafdd5ccd05c18e061aa"
        tradSS = (
            "78d093eca7248340a89dd0109f6f460f0cd7d4d0337b3121695870ee1d0afdee"
            "312e47708c4fa2f7798ef8fbd02ea0da"
        )
        tradCT = (
            "04b8bec46bf81ac8bd1eabf8d6e9dff02439a1e44e0e65a6df7a73f0b213b331"
            "abd51422fb0d732f3717f5d7955c267a08648998f793fac2112e7abd8a8bfc5fe"
            "3323acaba0272e4e2e95b5ec8508e93998a26338df5249cb09fd7b421cecd260b"
        )
        tradPK = (
            "04945e7f006691a33aeddd4b9f1a63cf2b322269225a4e20fbf5fd7448038c7a"
            "a27a9ed02998486dc3cb281a8d461db63ad3e7eed8e3960333a60f6e6b295a36b"
            "c109be18e3bbf9eb7495b6a2badedc81f7b554edb5c940d14f3ee903788c7dec4"
        )

        trad_key = generate_key("ecdh", curve="secp384r1")
        pq_key = generate_key("ml-kem-1024")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual(f"composite-kem-{COMPOSITE_KEM_VERSION}-ml-kem-1024-ecdh-secp384r1", comp_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.63", str(comp_key.get_oid()))
        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual(f"composite-kem-{COMPOSITE_KEM_VERSION}-ml-kem-1024-ecdh-secp384r1", comp_private_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.63", str(comp_private_key.get_oid()))
        ss_expected = "9704485a39219ae696eb9978d24d7641bb2743b1412844808e81cc00afc174ca"
        ss = comp_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
        )
        self.assertEqual(
            ss_expected,
            ss.hex(),
            "id-MLKEM1024-ECDH-P384-HMAC-SHA512 Combiner function output does not match expected value.",
        )

        ss2 = comp_private_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
        )
        self.assertEqual(
            ss_expected,
            ss2.hex(),
            "id-MLKEM1024-ECDH-P384-HMAC-SHA512 Combiner "
            "function output does not match expected value from private key.",
        )


if __name__ == "__main__":
    unittest.main()