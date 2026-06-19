# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The MockCA→verifier hop sends respInfo as a plain JSON object.

Unit-tests the HTTP body :class:`VeraisonVerifier.submit_evidence` constructs
(without performing real HTTP): the respInfo must be carried under the
``resp_info_json`` field as a JSON object — not base64, not DER.
"""

import unittest
from unittest import mock

from mock_ca.remote_att_mockca.attestation_verifier import VeraisonVerifier


class _FakeResponse:
    """Minimal stand-in for ``requests.Response`` (HTTP 200 + EAR JWT)."""

    ok = True
    status_code = 200
    text = ""

    def json(self) -> dict:
        return {"ear": "fake.ear.jwt"}


class SubmitRespInfoJsonTest(unittest.TestCase):
    """``submit_evidence`` carries respInfo as JSON, never base64/DER."""

    def _capture_post_body(self, **submit_kwargs) -> dict:
        """Call submit_evidence with HTTP + EAR checks stubbed; return the body."""
        client = VeraisonVerifier(base_url="http://tpm-verifier:8444")
        captured: dict = {}

        def fake_post(url, json=None, **_kwargs):  # noqa: A002 - mirrors requests API
            captured["url"] = url
            captured["body"] = json
            return _FakeResponse()

        # The HTTP client + EAR checks now live in libattest.ra.verifier_client
        # (the MockCA class is a thin alias). EAR verification is fail-closed, so
        # provide a non-None key and stub the signature check to pass.
        with mock.patch(
            "libattest.ra.verifier_client.requests.post",
            side_effect=fake_post,
        ), mock.patch.object(
            VeraisonVerifier, "_fetch_ear_public_key", return_value=object()
        ), mock.patch(
            "libattest.ra.verifier_client.verify_ear_jwt",
            return_value=True,
        ), mock.patch(
            "libattest.ra.verifier_client.ear_is_affirming",
            return_value=True,
        ):
            ear = client.submit_evidence(**submit_kwargs)

        self.assertEqual(ear, "fake.ear.jwt")
        return captured["body"]

    def test_resp_info_json_is_plain_json_object(self) -> None:
        resp_info = {"pcrs": [0, 1, 2, 3, 4], "hashAlgId": 0x000B}
        body = self._capture_post_body(
            nonce=b"\x00" * 32,
            evidence=b"\x30\x00",
            evidence_oid="2.23.133.20.2",
            resp_info_json=resp_info,
        )

        # respInfo is carried verbatim as a JSON object.
        self.assertIn("resp_info_json", body)
        self.assertEqual(body["resp_info_json"], resp_info)
        # The legacy base64/DER field must be gone.
        self.assertNotIn("pcr_selection", body)
        # The nonce / evidence remain base64-encoded as before.
        self.assertIsInstance(body["nonce"], str)
        self.assertIsInstance(body["evidence"], str)
        self.assertEqual(body["oid"], "2.23.133.20.2")

    def test_resp_info_json_omitted_when_absent(self) -> None:
        body = self._capture_post_body(
            nonce=b"\x01" * 16,
            evidence=b"\x30\x00",
            evidence_oid="2.23.133.20.2",
        )
        self.assertNotIn("resp_info_json", body)
        self.assertNotIn("pcr_selection", body)


if __name__ == "__main__":
    unittest.main()
