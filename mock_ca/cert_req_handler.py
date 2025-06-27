# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Handles certificate request messages of type 'ir', 'cr', 'p10cr', and 'kur'."""

import logging
from typing import List, Optional

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480, rfc9481

from mock_ca.mock_fun import MockCAState
from mock_ca.operation_dbs import NonSigningKeyCertsAndKeys
from pq_logic.hybrid_sig.chameleon_logic import load_chameleon_csr_delta_key_and_sender
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources import keyutils
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import (
    build_ccp_from_ccr,
    build_cp_cmp_message,
    build_cp_from_p10cr,
    build_ip_cmp_message,
    build_kup_from_kur,
    build_unsuccessful_ca_cert_response,
    set_ca_header_fields,
)
from resources.certbuildutils import prepare_extensions
from resources.certutils import (
    build_cmp_chain_from_pkimessage,
    check_is_cert_signer,
    validate_key_usage,
)
from resources.checkutils import (
    check_generalinfo_field,
    check_if_response_contains_encrypted_cert,
    check_is_protection_present,
    check_message_time_field,
    check_sender_cmp_protection,
    validate_cert_profile_for_ca,
    validate_request_message_nonces_and_tx_id,
    validate_senderkid_for_cmp_protection,
    validate_wrong_integrity,
)
from resources.cmputils import (
    build_cmp_error_message,
    find_oid_in_general_info,
    get_cmp_message_type,
    get_pkistatusinfo,
    patch_generalinfo,
)
from resources.convertutils import ensure_is_verify_key
from resources.copyasn1utils import copy_name
from resources.data_objects import ExtraIssuingData
from resources.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadCertTemplate,
    BadMessageCheck,
    BadRequest,
    BadTime,
    BodyRelevantError,
    CMPTestSuiteError,
    InvalidKeyData,
    NotAuthorized,
    SignerNotTrusted,
    TransactionIdInUse,
    UnsupportedVersion,
    WrongIntegrity,
)
from resources.keyutils import load_public_key_from_cert_template
from resources.protectionutils import (
    get_protection_type_from_pkimessage,
    validate_orig_pkimessage,
    verify_pkimessage_protection,
)
from resources.suiteenums import ProtectedType
from resources.typingutils import SignKey
from resources.utils import get_openssl_name_notation
from unit_tests.utils_for_test import load_env_data_certs

# (Make sure to import all the required functions and exceptions, for example:
#  build_cp_cmp_message, build_cp_from_p10cr, build_ip_cmp_message, build_kup_from_kur,
#  find_oid_in_general_info, verify_hybrid_pkimessage_protection, verify_pkimessage_protection,
#  BadMessageCheck, etc.)


class CertReqHandler:
    """Handles certificate request messages of type 'ir', 'cr', 'p10cr', and 'kur'."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: SignKey,
        state: MockCAState,
        cert_conf_handler,
        cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
        extensions: Optional[rfc9480.Extensions] = None,
        shared_secrets: Optional[bytes] = None,
        xwing_key: Optional[HybridKEMPrivateKey] = None,
        kga_key: Optional[SignKey] = None,
        kga_cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
        issuing_db: Optional[NonSigningKeyCertsAndKeys] = None,
    ):
        """Initialize the certificate request handler.

        :param ca_cert: The CA certificate.
        :param ca_key: The CA private key.
        :param state: The overall CA state.
        :param cert_conf_handler: The certificate confirmation handler.
        :param extensions: A list of extensions (e.g. OCSP, CRL) to include in responses.
        :param shared_secrets: The shared secret used for MAC protection.
        :param xwing_key: Optional fallback key for verifying password-based protection.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.state = state
        self.cert_conf_handler = cert_conf_handler
        self.extensions = extensions  # Now a unified list of extensions

        if extensions is None:
            ca_pub_key = ensure_is_verify_key(self.ca_key.public_key())
            self.extensions = prepare_extensions(ca_key=ca_pub_key, critical=False)

        self.pre_shared_secret = shared_secrets
        self.xwing_key = xwing_key
        self.must_be_protected = True
        self.check_time = True
        self.allowed_interval = 500
        self.allow_same_key_cert_req = False
        self.allow_same_key_kur = False
        self.sender = "CN=Mock-CA"
        self.kga_key = kga_key
        self.kga_cert_chain = kga_cert_chain
        self.issuing_db = issuing_db
        self.enforce_lwcmp_alg_profile = False

        self.issuing_params = load_env_data_certs()

        self.cmp_protection_cert = cmp_protection_cert
        self.extra_issuing_data = ExtraIssuingData(
            regToken="SuperSecretRegToken",
            authenticator="MaidenName",
        )
        self.issuing_params.update(
            {
                "kga_cert_chain": self.kga_cert_chain,
                "kga_key": self.kga_key,
                "password": self.pre_shared_secret,
                "sender": self.sender,
                "cmp_protection_cert": self.cmp_protection_cert,
                "extensions": self.extensions,
                "ca_cert": self.ca_cert,
                "ca_key": self.ca_key,
                "extra_issuing_data": self.extra_issuing_data,
            }
        )

        self.cert_db = self.state.certificate_db
        self.cross_signed_certs: List[rfc9480.CMPCertificate] = []

    def get_cross_signed_certs(self) -> List[rfc9480.CMPCertificate]:
        """Get the list of cross-signed certificates."""
        return self.cross_signed_certs

    @staticmethod
    def is_certificate_in_list(cert_template: rfc9480.CertTemplate, cert_list: List[rfc9480.CMPCertificate]) -> bool:
        """Check if the certificate template is in the list of certificates.

        :param cert_template: The certificate template to check.
        :param cert_list: The list of certificates to check against.
        :return: `True` if the certificate is in the list, `False` otherwise.
        """
        name_obj = copy_name(filled_name=cert_template["subject"], target=rfc9480.Name())
        subject_der = encoder.encode(name_obj)
        public_key = load_public_key_from_cert_template(cert_template, must_be_present=False)
        if public_key is None:
            return False

        for candidate in cert_list:
            candidate_subject_der = encoder.encode(candidate["tbsCertificate"]["subject"])
            if candidate_subject_der == subject_der:
                loaded_pub_key = keyutils.load_public_key_from_spki(candidate["tbsCertificate"]["subjectPublicKeyInfo"])
                if loaded_pub_key == public_key:
                    return True

        return False

    def check_same_key_cert_request(self, pki_message: PKIMessageTMP) -> None:
        """Check if the certificate template is already in the list of certificates."""
        if self.allow_same_key_cert_req and pki_message["body"].getName() in ["ir", "cr", "p10cr", "ccr"]:
            return

        if self.allow_same_key_kur and pki_message["body"].getName() == "kur":
            return

        if pki_message["body"].getName() == "p10cr":
            csr = pki_message["body"]["p10cr"]
            spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]

            if spki["subjectPublicKey"].asOctets() == b"":
                return

            try:
                loaded_pub_key = keyutils.load_public_key_from_spki(spki)
            except (InvalidKeyData, BadAsn1Data, BadAlg) as e:
                raise BodyRelevantError(
                    e.message, "badCertTemplate", pki_message=pki_message, error_details=e.get_error_details()
                )

            if loaded_pub_key is not None:
                if self.state.contains_pub_key(loaded_pub_key, csr["certificationRequestInfo"]["subject"]):
                    raise BadCertTemplate("The public key is already defined for the user.")

            try:
                public_key, _ = load_chameleon_csr_delta_key_and_sender(csr=pki_message["body"]["p10cr"])
                if self.state.contains_pub_key(public_key, csr["certificationRequestInfo"]["subject"]):
                    raise BadCertTemplate("The chameleon delta public key is already defined for the user.")
            except ValueError:
                pass

        else:
            body_name = pki_message["body"].getName()

            for entry in pki_message["body"][body_name]:
                cert_template = entry["certReq"]["certTemplate"]
                try:
                    if self.is_certificate_in_list(cert_template, self.state.issued_certs):
                        _name = get_openssl_name_notation(cert_template["subject"])
                        raise BadCertTemplate(f"The public key is already defined for the user: {_name}")
                except (InvalidKeyData, BadAsn1Data, BadAlg) as e:
                    raise BodyRelevantError(
                        e.message, "badCertTemplate", pki_message=pki_message, error_details=e.get_error_details()
                    )
                public_key = load_public_key_from_cert_template(cert_template, must_be_present=False)
                if public_key is not None:
                    if self.state.contains_pub_key(public_key, cert_template["subject"]):
                        raise BadCertTemplate("The public key is already defined for the user.")

    def _get_for_mac(self, request: PKIMessageTMP) -> bool:
        """Determine if the message is for MAC protection."""
        for_mac = False
        if request["header"]["protectionAlg"].isValue:
            prot_type = get_protection_type_from_pkimessage(
                pki_message=request,
            )
            for_mac = prot_type == "mac"
        return for_mac

    def _add_cert_to_state(self, cert: rfc9480.CMPCertificate) -> None:
        """Add a certificate to the state."""
        self.state.issued_certs.append(cert)

    def add_request_for_cert_conf(
        self, request: PKIMessageTMP, response: PKIMessageTMP, certs: List[rfc9480.CMPCertificate]
    ) -> None:
        """Add a successful request to the state."""
        self.cert_conf_handler.add_request(pki_message=request)
        self.cert_conf_handler.add_response(pki_message=response, certs=certs)

    def process_after_request(
        self,
        request: PKIMessageTMP,
        response: PKIMessageTMP,
        certs: List[rfc9480.CMPCertificate],
    ) -> PKIMessageTMP:
        """Process the request after it has been handled successfully.

        :param request: The original request.
        :param response: The response to the request.
        :param certs: The list of certificates.
        """
        response_body_type = get_cmp_message_type(response)
        if response_body_type not in ["ip", "cp", "ccp", "kup"]:
            return response

        status_info = get_pkistatusinfo(response)
        if status_info["status"].prettyPrint() == "rejection":
            return response

        confirm_ = CertReqHandler.check_if_used(
            request=request,
            response=response,
        )
        self.state.store_transaction_certificate(pki_message=request, certs=certs)

        if confirm_:
            response = patch_generalinfo(
                msg_to_patch=response,
                implicit_confirm=True,
            )

        if confirm_ and response_body_type == "ccp":
            self.cross_signed_certs.extend(certs)

        if response_body_type == "kup":
            self.state.add_may_update_cert(
                old_cert=request["extraCerts"][0],
                update_cert=certs[0],
                was_confirmed=confirm_,
            )
        if confirm_:
            self.state.add_certs(certs=certs)
            self.cert_conf_handler.add_confirmed_certs(request)
        else:
            self.state.add_certs(certs=certs, was_confirmed=False)
            self.add_request_for_cert_conf(request=request, response=response, certs=certs)

        return response

    def _validate_orig_req(self, pki_message: PKIMessageTMP) -> None:
        """Validate the original message and the protection."""
        validate_orig_pkimessage(pki_message, must_be_present=False, password=self.pre_shared_secret)

    def process_ir(
        self,
        pki_message: PKIMessageTMP,
        verify_ra_verified: bool = True,
    ) -> "PKIMessageTMP":
        """Process an initialization request (IR) message.

        :param pki_message: The received `PKIMessage`.
        :param verify_ra_verified: If the `raVerified` fields should be validated. Defaults to `True`.
        :return: The response `PKIMessage`.
        """
        logging.debug("CertReqHandler: Processing IR message")
        logging.debug("Verify RA verified: %s", verify_ra_verified)

        for_mac = self._get_for_mac(request=pki_message)
        response, certs = build_ip_cmp_message(
            request=pki_message,
            implicit_confirm=False,
            verify_ra_verified=verify_ra_verified,
            for_mac=for_mac,
            **self.issuing_params,
        )

        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )

    def check_signer_is_a_issued_cert(self, pki_message: PKIMessageTMP) -> None:
        """Check if the signer of the CR message known to the CA, by being an issued certificate."""
        if pki_message["header"]["protectionAlg"].isValue:
            prot_type = ProtectedType.get_protection_type(pki_message)

            if prot_type in [ProtectedType.DH, ProtectedType.KEM]:
                result = True
            elif prot_type == ProtectedType.MAC:
                result = False
            else:
                result = True

            if pki_message["extraCerts"].isValue and result:
                cert = pki_message["extraCerts"][0]
                body_name = pki_message["body"].getName()
                if not self.state.contains_cert(cert):
                    raise NotAuthorized(
                        f"The certificate was not found in the state. {body_name} messages are only "
                        "allowed for known certificates."
                    )

    def process_cr(self, pki_message: PKIMessageTMP, verify_ra_verified: bool = True):
        """Process a certificate request (CR) message.

        :param pki_message: The received `PKIMessage`.
        :param verify_ra_verified: If the `raVerified` fields should be validated. Defaults to `True`.
        :return: The response `PKIMessage`.
        """
        logging.debug("CertReqHandler: Processing CR message")
        for_mac = self._get_for_mac(request=pki_message)
        self.check_signer_is_a_issued_cert(pki_message)

        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            implicit_confirm=False,
            extensions=self.extensions,
            sender=self.sender,
            for_mac=for_mac,
            verify_ra_verified=verify_ra_verified,
        )

        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )

    def process_p10cr(self, pki_message: PKIMessageTMP, verify_ra_verified: bool = True):
        """Process a `P10CR` message.

        :param pki_message: The received `PKIMessage`.
        :param verify_ra_verified: If the `raVerified` fields should be validated. Defaults to `True`
        :return: The response `PKIMessage`.
        """
        logging.debug("CertReqHandler: Processing P10CR message")
        self.state.cert_state_db.check_request_for_compromised_key(pki_message)

        for_mac = self._get_for_mac(request=pki_message)
        logging.info("Processing P10CR message")

        response, cert = build_cp_from_p10cr(
            request=pki_message,
            set_header_fields=True,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            implicit_confirm=False,
            extensions=self.extensions,
            sender=self.sender,
            for_mac=for_mac,
            include_csr_extensions=False,
            include_ski=True,
            verify_ra_verified=verify_ra_verified,
        )
        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=[cert],
        )

    def process_kur(self, pki_message: PKIMessageTMP):
        """Process a key update request (KUR) message.

        :param pki_message: The received `PKIMessage`.
        :return: The response `PKIMessage`.
        """
        logging.debug("CertReqHandler: Processing KUR message")

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("Protection algorithm was not set.")

        prot_type = ProtectedType.get_protection_type(pki_message)

        if prot_type == ProtectedType.MAC:
            raise WrongIntegrity("The key updated request was MAC protected")

        if prot_type in [ProtectedType.DH, ProtectedType.KEM]:
            logging.debug("CertReqHandler: Processing KUR message with %s protection", prot_type.value)

        self.check_signer_is_a_issued_cert(pki_message)

        if prot_type == ProtectedType.KEM:
            verify_pkimessage_protection(
                pki_message=pki_message,
                shared_secret=self.state.get_kem_mac_shared_secret(pki_message=pki_message),
            )

            if not pki_message["extraCerts"].isValue:
                raise BadRequest("The extraCerts field MUST be set for `KEM` KUR messages.")
            response, certs = build_ip_cmp_message(
                request=pki_message,
                implicit_confirm=False,
                verify_ra_verified=False,
                for_mac=True,
                **self.issuing_params,
            )

            # TODO fix for KEM and keyAgreement keys.
            tmp = PKIMessageTMP()
            tmp["header"] = response["header"]
            if response["body"]["ip"]["caPubs"].isValue:
                tmp["body"]["kup"]["caPubs"] = response["body"]["ip"]["caPubs"]
            tmp["body"]["kup"]["response"] = response["body"]["ip"]["response"]
            response = tmp

        else:
            verify_hybrid_pkimessage_protection(pki_message=pki_message)

            response, certs = build_kup_from_kur(
                request=pki_message,
                implicit_confirm=False,
                allow_same_key=self.allow_same_key_kur,
                **self.issuing_params,
            )

        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )

    def check_message_time(self, pki_message: PKIMessageTMP) -> None:
        """Check if the message time is within the allowed time interval."""
        if self.check_time:
            if not pki_message["header"]["messageTime"].isValue:
                raise BadTime("The message time was not set.")

            check_message_time_field(
                pki_message=pki_message,
                allowed_interval=self.allowed_interval,
            )

    @staticmethod
    def check_if_used(request: PKIMessageTMP, response: PKIMessageTMP) -> bool:
        """Check if the request is automatically confirmed.

        :param request: The request to check if the implicit confirm was set.
        :param response: The response to check if an encrypted certificate is returned.
        :return: `True` if the request is/can be automatically confirmed, `False` otherwise.
        """
        body_name = request["body"].getName()

        if body_name in {"p10cr", "ccr", "krp"}:
            return find_oid_in_general_info(request, str(rfc9480.id_it_implicitConfirm))

        if body_name not in {"ir", "cr", "kur"}:
            return False

        if not find_oid_in_general_info(request, str(rfc9480.id_it_implicitConfirm)):
            return False

        return not check_if_response_contains_encrypted_cert(
            response,
        )

    @staticmethod
    def validate_nonces_and_tx_id(pki_message: PKIMessageTMP) -> None:
        """Validate the nonces and the `transactionID` of a `PKIMessage`."""
        validate_request_message_nonces_and_tx_id(pki_message)

    @staticmethod
    def validate_general_info(pki_message: PKIMessageTMP) -> None:
        """Validate the general info of a PKIMessage."""
        check_generalinfo_field(pki_message=pki_message)
        validate_cert_profile_for_ca(pki_message, cert_profiles=["base"])

    @staticmethod
    def check_signer(pki_message: PKIMessageTMP) -> None:
        """Check if the signer is trusted."""
        if not pki_message["extraCerts"].isValue:
            raise BadMessageCheck("The extraCerts field was not set.")

        cert_chain = build_cmp_chain_from_pkimessage(
            pki_message=pki_message,
            ee_cert=pki_message["extraCerts"][0],
        )
        if len(cert_chain) == 1:
            raise SignerNotTrusted("The certificate chain was not present.")

        if not check_is_cert_signer(cert_chain[-1], cert_chain[-1]):
            raise SignerNotTrusted("The last certificate in the chain was not a signer.")

        # Verify that the CMP-protection certificate is authorized to sign the message.
        # Allows the CMP protection certificate to have an unset key usage.
        validate_key_usage(cert_chain[0], key_usages="digitalSignature", strictness="LAX")

    def validate_header(
        self,
        pki_message: PKIMessageTMP,
        must_be_protected: Optional[bool] = None,
        for_nested: bool = False,
    ) -> None:
        """Validate the header of a PKIMessage."""
        if int(pki_message["header"]["pvno"]) not in [2, 3]:
            raise UnsupportedVersion("The protocol version number was not 2 or 3.")

        if must_be_protected is None:
            must_be_protected = self.must_be_protected

        if not for_nested:
            validate_request_message_nonces_and_tx_id(request=pki_message)
        self.validate_general_info(pki_message=pki_message)
        self.check_message_time(pki_message=pki_message)
        check_is_protection_present(pki_message, must_be_protected=must_be_protected)
        validate_wrong_integrity(pki_message)
        check_sender_cmp_protection(pki_message, must_be_protected=must_be_protected, allow_failure=False)
        validate_senderkid_for_cmp_protection(pki_message, must_be_protected=must_be_protected, allow_mac_failure=False)
        oid = pki_message["header"]["protectionAlg"]["algorithm"]
        if pki_message["header"]["protectionAlg"].isValue:
            prot_type2 = ProtectedType.get_protection_type(pki_message)
            if prot_type2 not in [ProtectedType.MAC, ProtectedType.KEM, ProtectedType.DH]:
                self.check_signer(pki_message)

            elif prot_type2 in [ProtectedType.DH, ProtectedType.KEM]:
                logging.debug("CertReqHandler: Processing KEM/DH protection")

            else:
                if self.enforce_lwcmp_alg_profile:
                    if oid not in [rfc9480.id_PasswordBasedMac, rfc9481.id_PBMAC1]:
                        raise BadAlg(
                            "For LwCMP is only `PasswordBasedMac` and `PBMAC1` as protection algorithm allowed."
                        )

    def build_cert_resp_error_response(self, e: CMPTestSuiteError, request: PKIMessageTMP) -> PKIMessageTMP:
        """Build an error response for an IR message.

        :param e: The exception that caused the error.
        :return: The error response.
        """
        return build_unsuccessful_ca_cert_response(
            sender=self.sender,
            request=request,
            failinfo=e.get_failinfo(),
            text=[e.message] + e.get_error_details(),
        )

    def error_body(self, e: CMPTestSuiteError, request: PKIMessageTMP) -> PKIMessageTMP:
        """Build an error response for an IR message."""
        kwargs = set_ca_header_fields(request, {})
        pki_message = build_cmp_error_message(
            request=request,
            sender=self.sender,
            status="rejection",
            failinfo=e.get_failinfo(),
            text=[e.message] + e.get_error_details(),
            **kwargs,
        )
        return pki_message

    def check_cert_is_updated(self, pki_message: PKIMessageTMP) -> None:
        """Check if the certificate is updated.

        :param pki_message: The PKIMessage to check.
        :raises CertRevoked: If the certificate is revoked.
        """
        if pki_message["extraCerts"].isValue:
            body_name = get_cmp_message_type(pki_message)
            strict = body_name != "kur"
            self.cert_db.update_state.validate_is_updated(
                cert=pki_message["extraCerts"][0], body_name=body_name, allow_timeout=strict
            )

    def process_cert_request(
        self,
        pki_message: PKIMessageTMP,
        verify_ra_verified: bool = True,
        must_be_protected: Optional[bool] = None,
    ) -> "PKIMessageTMP":
        """Process a certificate request message.

        :param pki_message: The incoming PKIMessage.
        :param verify_ra_verified: If the RA verified the request.
        :param must_be_protected: If the message must be protected (only needed for
        `nested` messages). Defaults to `None`.
        (uses the `must_be_protected` attribute of the class if `None`).
        raise the exception to the nested request handler. Defaults to `False`.
        :return: The processed PKI response.
        :raises NotImplementedError: If the message type is unsupported.
        """
        # raise exception for the error body.
        self.validate_header(pki_message, must_be_protected=must_be_protected)

        msg_type = pki_message["body"].getName()
        if msg_type not in ["ir", "cr", "p10cr", "kur", "ccr"]:
            raise NotImplementedError(f"Message type '{msg_type}' is not supported by CertReqHandler.")
        try:
            validate_wrong_integrity(
                pki_message=pki_message,
            )
            self.check_same_key_cert_request(pki_message=pki_message)
            self.check_cert_is_updated(pki_message=pki_message)
            self._validate_orig_req(pki_message=pki_message)

            if msg_type == "ir":
                response = self.process_ir(pki_message, verify_ra_verified=verify_ra_verified)
            elif msg_type == "cr":
                response = self.process_cr(pki_message, verify_ra_verified=verify_ra_verified)
            elif msg_type == "p10cr":
                response = self.process_p10cr(pki_message, verify_ra_verified=verify_ra_verified)
            elif msg_type == "kur":
                response = self.process_kur(pki_message)
            elif msg_type == "ccr":
                response = self.handle_cross_cert_req(pki_message)
            else:
                raise NotImplementedError(f"Message type '{msg_type}' is not supported by CertReqHandler.")

        except TransactionIdInUse as e:
            logging.error("Transaction ID in use: %s", e, exc_info=True)
            return self.error_body(e, request=pki_message)

        except CMPTestSuiteError as e:
            return self.build_cert_resp_error_response(e, pki_message)

        return response

    def handle_cross_cert_req(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Handle cross-certification requests."""
        # Only MSG-SIG-ALg is allowed for cross-certification requests.
        response, certs = build_ccp_from_ccr(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            extensions=self.extensions,
            for_mac=False,
            implicit_confirm=False,
        )
        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )
