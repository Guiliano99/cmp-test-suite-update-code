from pyasn1.type import univ

from pq_logic.tmp_oids import (
    id_keyAttestEvidence,
    id_it_keyAttestChall,
    id_it_keyAttestResp,
)


def test_evidence_oid_dotted():
    assert str(id_keyAttestEvidence) == "1.3.6.1.4.1.99999.2"


def test_chall_itav_oid_dotted():
    assert str(id_it_keyAttestChall) == "1.3.6.1.4.1.99999.2.1"


def test_resp_itav_oid_dotted():
    assert str(id_it_keyAttestResp) == "1.3.6.1.4.1.99999.2.2"


def test_all_are_object_identifiers():
    for oid in (id_keyAttestEvidence, id_it_keyAttestChall, id_it_keyAttestResp):
        assert isinstance(oid, univ.ObjectIdentifier)
