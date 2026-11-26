# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0
"""Check the pyasn1 facts that the auditing-pyasn1 skill states.

Each claim has an expected result. The script measures it with the installed pyasn1, writes one line per claim and
exits 1 if a claim does not hold, so that the skill can be checked again after a pyasn1 update. The number in
brackets is the number of the claim; the skill cites claims by it, so a new claim goes at the end of the list.

Run it from the repository root with the interpreter of the project:
`.venv/bin/python .agents/skills/auditing-pyasn1/scripts/check_pyasn1_facts.py`.
"""

from __future__ import annotations

import copy
import datetime
import sys
from collections.abc import Callable

import pyasn1
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import base, namedtype, tag, univ, useful
from pyasn1_alt_modules import rfc4211, rfc5280

Check = Callable[[], tuple[bool, str]]
CLAIMS: list[tuple[str, Check]] = []

IMPLICIT_0 = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
EXPLICIT_0 = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
IMPLICIT_1 = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
EXPLICIT_2 = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
OCSP = univ.ObjectIdentifier("1.3.6.1.5.5.7.48.1")


def der(value: base.Asn1Type) -> str:
    """Return the DER of `value` as hex, or the name of the error that encoding raises."""
    try:
        return encoder.encode(value).hex()
    except PyAsn1Error as error:
        return f"raises {type(error).__name__}"


def raises(action: Callable[[], object]) -> str:
    """Run `action`; return 'no error', or the name and the start of the message of the PyAsn1Error it raises."""
    try:
        action()
    except PyAsn1Error as error:
        return f"raises PyAsn1Error: {str(error)[:60]}"
    return "no error"


def nulls() -> dict[str, univ.Null]:
    """Return a NULL value untagged, with IMPLICIT [0] and with EXPLICIT [0]."""
    return {
        "untagged": univ.Null(""),
        "IMPLICIT [0]": univ.Null("").subtype(implicitTag=IMPLICIT_0),
        "EXPLICIT [0]": univ.Null("").subtype(explicitTag=EXPLICIT_0),
    }


def algorithm_identifier(spec: univ.Sequence) -> univ.Sequence:
    """Fill an AlgorithmIdentifier-shaped SEQUENCE: sha256WithRSAEncryption with NULL parameters."""
    spec["algorithm"] = univ.ObjectIdentifier("1.2.840.113549.1.1.11")
    spec["parameters"] = univ.Null("")
    return spec


def sequences() -> dict[str, univ.Sequence]:
    """Return the same SEQUENCE value untagged, with IMPLICIT [1] and with EXPLICIT [2]."""
    return {
        "untagged": algorithm_identifier(rfc5280.AlgorithmIdentifier()),
        "IMPLICIT [1]": algorithm_identifier(rfc5280.AlgorithmIdentifier().subtype(implicitTag=IMPLICIT_1)),
        "EXPLICIT [2]": algorithm_identifier(rfc5280.AlgorithmIdentifier().subtype(explicitTag=EXPLICIT_2)),
    }


def directory_name(rdn_sequence: rfc5280.RDNSequence) -> rfc5280.Name:
    """Return the directoryName field ([4] EXPLICIT) of a new GeneralName that holds `rdn_sequence`."""
    general_name = rfc5280.GeneralName()
    general_name["directoryName"]["rdnSequence"] = rdn_sequence
    return general_name["directoryName"]


def cleared_rdn_sequence() -> rfc5280.RDNSequence:
    """Return an empty RDNSequence that has a value; a new RDNSequence() is a schema object."""
    value = rfc5280.RDNSequence()
    value.clear()
    return value


def add(text: str, check: Check) -> None:
    """Add a claim and the function that measures it."""
    CLAIMS.append((text, check))


# --- clone() of a single value (NULL), untagged, IMPLICIT and EXPLICIT ------------------------------------------


def null_claims(name: str, value: univ.Null) -> None:
    """Add the clone claims for one NULL value."""

    def same_object() -> tuple[bool, str]:
        clone = value.clone()
        return clone is value, f"clone is value: {clone is value}, DER {der(value)} -> {der(clone)}"

    def new_object() -> tuple[bool, str]:
        clone = value.clone("")
        kept = clone.tagSet == value.tagSet
        return clone is not value and kept, f"new object: {clone is not value}, same tagSet: {kept}, DER {der(clone)}"

    add(f"NULL {name}: clone() without arguments returns the same object, not a copy", same_object)
    add(f"NULL {name}: clone('') is a new object with the same type and tags", new_object)


# --- clone() of a SEQUENCE, untagged, IMPLICIT and EXPLICIT -------------------------------------------------------


def sequence_claims(name: str, value: univ.Sequence) -> None:
    """Add the clone claims for one SEQUENCE value."""

    def type_only() -> tuple[bool, str]:
        clone = value.clone()
        kept = clone.tagSet == value.tagSet
        return (
            kept and not clone.isValue and der(clone).startswith("raises"),
            f"same tagSet: {kept}, isValue {value.isValue} -> {clone.isValue}, DER {der(value)} -> {der(clone)}",
        )

    def with_values() -> tuple[bool, str]:
        clone = value.clone(cloneValueFlag=True)
        return clone is not value and der(clone) == der(value), f"new object: {clone is not value}, DER {der(clone)}"

    def shares_components() -> tuple[bool, str]:
        clone = value.clone(cloneValueFlag=True)
        shared = clone["algorithm"] is value["algorithm"]
        return shared, f"clone['algorithm'] is value['algorithm']: {shared}"

    add(f"SEQUENCE {name}: clone() copies the type and the tags, not the fields (no value, no DER)", type_only)
    add(f"SEQUENCE {name}: clone(cloneValueFlag=True) is a new object with the same DER", with_values)
    add(f"SEQUENCE {name}: clone(cloneValueFlag=True) shares the simple components", shares_components)


for _name, _null in nulls().items():
    null_claims(_name, _null)
for _name, _sequence in sequences().items():
    sequence_claims(_name, _sequence)


# --- clone() and the tag of a field ------------------------------------------------------------------------------


def field_tag_travels() -> tuple[bool, str]:
    """Measure that the clone of a tagged field keeps the tag of the field, which a new object does not have."""
    field = directory_name(cleared_rdn_sequence())
    clone = field.clone(cloneValueFlag=True)
    plain = rfc5280.Name()
    plain["rdnSequence"] = cleared_rdn_sequence()
    return (
        clone.tagSet == field.tagSet and clone.tagSet != plain.tagSet and der(clone) == "a4023000",
        f"DER of the clone {der(clone)}, of a new rfc5280.Name {der(plain)}",
    )


def untagged_into_tagged_field() -> tuple[bool, str]:
    """Measure that an untagged Name cannot be assigned to the EXPLICIT [4] directoryName field."""
    name = rfc5280.Name()
    name["rdnSequence"] = cleared_rdn_sequence()
    general_name = rfc5280.GeneralName()
    try:
        general_name["directoryName"] = name
    except KeyError as error:
        return "tag-incompatible" in str(error), f"raises KeyError: {str(error)[:50]}"
    return False, "no error"


def clone_with_schema_sequence_of() -> tuple[bool, str]:
    """Measure that a new, empty SEQUENCE OF in a field encodes, but that the field cannot be cloned with values."""
    field = directory_name(rfc5280.RDNSequence())
    encoded = der(field)
    result = raises(lambda: field.clone(cloneValueFlag=True))
    return encoded == "a4023000" and result.startswith("raises"), f"DER {encoded}, clone(cloneValueFlag=True) {result}"


add("The clone of the directoryName field ([4] EXPLICIT) keeps the field tag; a new Name has none", field_tag_travels)
add(
    "An untagged Name assigned to the directoryName field ([4] EXPLICIT) raises KeyError (tag-incompatible)",
    untagged_into_tagged_field,
)
add(
    "A new, empty SEQUENCE OF in a field encodes, but clone(cloneValueFlag=True) of the field raises",
    clone_with_schema_sequence_of,
)


# --- copy and deepcopy -------------------------------------------------------------------------------------------


def deepcopy_simple() -> tuple[bool, str]:
    """Measure copy.deepcopy of single values."""
    values = [univ.Integer(5), univ.Null("")]
    copies = [copy.deepcopy(v) for v in values]
    return all(der(c) == der(v) for c, v in zip(copies, values)), ", ".join(der(c) for c in copies)


def deepcopy_constructed() -> tuple[bool, str]:
    """Measure copy.deepcopy of constructed values whose fields all have values."""
    sequence_of = univ.SequenceOf(componentType=univ.Integer())
    sequence_of.extend([1, 2])
    results = [raises(lambda v=v: copy.deepcopy(v)) for v in (sequences()["untagged"], sequence_of)]
    return all(r.startswith("raises") for r in results), "; ".join(results)


def shallow_copy() -> tuple[bool, str]:
    """Measure copy.copy of a SEQUENCE."""
    value = sequences()["untagged"]
    duplicate = copy.copy(value)
    shared = duplicate["algorithm"] is value["algorithm"]
    return duplicate is not value and der(duplicate) == der(value) and shared, (
        f"new object: {duplicate is not value}, DER {der(duplicate)}, shares components: {shared}"
    )


add("copy.deepcopy of INTEGER and NULL values gives the same DER", deepcopy_simple)
add(
    "copy.deepcopy of an AlgorithmIdentifier and of a SEQUENCE OF raises PyAsn1Error, even with every field set",
    deepcopy_constructed,
)
add("copy.copy of a SEQUENCE is a new object with the same DER that shares the components", shallow_copy)


# --- reading fields, presence and truth values --------------------------------------------------------------------


def instantiate_false() -> tuple[bool, str]:
    """Measure getComponentByName(instantiate=False) on a set field whose isValue is False."""
    general_name = rfc5280.GeneralName()
    general_name["directoryName"]["rdnSequence"] = rfc5280.RDNSequence()
    description = rfc5280.AccessDescription()
    description["accessMethod"] = OCSP
    description["accessLocation"] = general_name
    read = description.getComponentByName("accessLocation", instantiate=False)
    return read is univ.noValue and der(description) == "300e06082b06010505073001a4023000", (
        f"read {type(read).__name__}, DER of the description {der(description)}"
    )


def omit_empty_optionals() -> tuple[bool, str]:
    """Measure encode(omitEmptyOptionals=False) on a CertTemplate without validity."""
    template = rfc4211.CertTemplate()
    template["version"] = 2
    plain = encoder.encode(template).hex()
    full = encoder.encode(template, omitEmptyOptionals=False).hex()
    return plain == "3003800102" and full == "3005800102a400", f"default {plain}, omitEmptyOptionals=False {full}"


def absent_optional() -> tuple[bool, str]:
    """Measure an absent OPTIONAL field."""
    field = rfc4211.CertTemplate()["serialNumber"]
    truth = raises(lambda: bool(field))
    absent = field is None
    present = field.isValue
    return not absent and not present and truth.startswith("raises"), (
        f"is None {absent}, isValue {present}, bool {truth}"
    )


def false_values() -> tuple[bool, str]:
    """Measure the truth value of valid values."""
    empty = univ.SequenceOf(componentType=univ.Integer())
    empty.clear()
    values = [univ.Integer(0), univ.Boolean(False), univ.OctetString(b""), empty]
    return all(v.isValue and not bool(v) for v in values), ", ".join(f"{der(v)} false" for v in values)


def named_bits() -> tuple[bool, str]:
    """Measure asOctets() of a BIT STRING against its DER."""
    bits = univ.BitString("101")
    octets = bits.asOctets().hex()
    return octets == "05" and der(bits) == "030205a0", f"asOctets {octets}, DER {der(bits)}"


def default_field() -> tuple[bool, str]:
    """Measure a DEFAULT field that was never set."""
    constraints = rfc5280.BasicConstraints()
    field = constraints["cA"]
    return field.isValue and not bool(field), f"isValue {field.isValue}, value {bool(field)}, DER {der(constraints)}"


class _AllOptional(univ.Sequence):
    """A SEQUENCE whose fields are all OPTIONAL."""

    componentType = namedtype.NamedTypes(namedtype.OptionalNamedType("a", univ.Integer()))


def all_optional() -> tuple[bool, str]:
    """Measure a SEQUENCE whose fields are all OPTIONAL when none is set."""
    value = _AllOptional()
    return value.isValue, f"isValue {value.isValue}, DER {der(value)}"


add("getComponentByName(name, instantiate=False) is noValue for a set field whose isValue is False", instantiate_false)
add("encode(omitEmptyOptionals=False) writes an absent CertTemplate validity as a400", omit_empty_optionals)
add("An absent OPTIONAL field: `is None` is False, isValue is False, bool() raises PyAsn1Error", absent_optional)
add("Valid values count as false: INTEGER 0, BOOLEAN FALSE, empty OCTET STRING, empty SEQUENCE OF", false_values)
add("BitString('101').asOctets() is 05, while the DER of the named bits 101 is 030205a0", named_bits)
add("A DEFAULT field (cA of BasicConstraints) has isValue True when it was never set", default_field)
add("A SEQUENCE whose fields are all OPTIONAL has isValue True when none is set", all_optional)


# --- an independent copy, trailing bytes, CHOICE, access by name, bytes, tags ---------------------------------------


def decoded_copy() -> tuple[bool, str]:
    """Measure the copy that is made by decoding the DER of a SEQUENCE or SEQUENCE OF with a clone of it as the spec."""
    results = []
    holds = True
    values = {f"AlgorithmIdentifier {name}": value for name, value in sequences().items()}
    values |= {f"RDNSequence {name}": value for name, value in tagged_rdn_sequences().items()}
    for name, value in values.items():
        copied, rest = decoder.decode(encoder.encode(value), asn1Spec=value.clone())
        independent = copied is not value and copied[0] is not value[0]
        holds = holds and independent and not rest and der(copied) == der(value)
        results.append(f"{name}: {der(copied)}, shares nothing: {independent}")
    return holds, "; ".join(results)


def trailing_bytes() -> tuple[bool, str]:
    """Measure that the decoder returns bytes after the structure as `rest` and raises no error."""
    value = sequences()["untagged"]
    _, rest = decoder.decode(encoder.encode(value) + b"\x00", asn1Spec=rfc5280.AlgorithmIdentifier())
    return rest == b"\x00", f"rest {rest.hex()}"


def unset_choice() -> tuple[bool, str]:
    """Measure getName() and getComponent() of a CHOICE that has no component."""
    choice = rfc5280.GeneralName()
    name, component = raises(choice.getName), raises(choice.getComponent)
    return (
        not choice.isValue and "Component not chosen" in name and "Component not chosen" in component,
        f"isValue {choice.isValue}, getName() {name}, getComponent() {component}",
    )


def access_by_name() -> tuple[bool, str]:
    """Measure that obj['field'] and getComponentByName('field') return the same object."""
    value = sequences()["untagged"]
    same = value["algorithm"] is value.getComponentByName("algorithm")
    return same, f"same object: {same}"


def octets_and_text() -> tuple[bool, str]:
    """Measure what asOctets(), str() and prettyPrint() return for an OCTET STRING."""
    value = univ.OctetString(b"\x01\xff")
    text = str(value)
    return (
        value.asOctets() == b"\x01\xff" and isinstance(text, str) and value.prettyPrint() == "0x01ff",
        f"asOctets {value.asOctets().hex()}, str() is a text of {len(text)} characters, "
        f"prettyPrint {value.prettyPrint()}",
    )


def equal_with_other_tag() -> tuple[bool, str]:
    """Measure that two INTEGER values compare equal when their tags differ, and that their DER differs."""
    plain = univ.Integer(5)
    tagged = univ.Integer(5).subtype(implicitTag=IMPLICIT_0)
    equal = plain == tagged
    return equal and der(plain) != der(tagged), f"equal: {equal}, DER {der(plain)} and {der(tagged)}"


def unset_truth_value() -> tuple[bool, str]:
    """Measure bool() of an object without a value, for a SEQUENCE, a CHOICE and three simple types."""
    results = {}
    for name, value in {
        "SEQUENCE": rfc5280.AlgorithmIdentifier(),
        "CHOICE": rfc5280.GeneralName(),
        "INTEGER": univ.Integer(),
        "OCTET STRING": univ.OctetString(),
        "SEQUENCE OF": rfc5280.RDNSequence(),
    }.items():
        try:
            results[name] = str(bool(value))
        except PyAsn1Error:
            results[name] = "raises"
    expected = dict.fromkeys(results, "raises") | {"SEQUENCE": "False", "CHOICE": "False"}
    return results == expected, ", ".join(f"{name} {result}" for name, result in results.items())


add(
    "An object without a value: bool() is False for SEQUENCE and CHOICE, raises for INTEGER, OCTET STRING, SEQUENCE OF",
    unset_truth_value,
)
add(
    "Decoding the DER with clone() of the value as the spec gives an independent copy (SEQUENCE, SEQUENCE OF, Name)",
    decoded_copy,
)
add("The decoder returns bytes after the structure as `rest` and raises no error", trailing_bytes)
add(
    "getName() and getComponent() of a CHOICE without a component raise PyAsn1Error: Component not chosen",
    unset_choice,
)
add("obj['field'] and getComponentByName('field') return the same object", access_by_name)
add("asOctets() returns the bytes of an OCTET STRING; str() returns a text, prettyPrint() a hex text", octets_and_text)
add("INTEGER values with different tags compare equal, but their DER differs", equal_with_other_tag)


# --- times -------------------------------------------------------------------------------------------------------


def generalized_time(moment: datetime.datetime) -> str:
    """Return the text that GeneralizedTime.fromDateTime writes for `moment`."""
    return str(useful.GeneralizedTime.fromDateTime(moment))


def time_fraction() -> tuple[bool, str]:
    """Measure that fromDateTime writes the microseconds as a fraction, and that replace(microsecond=0) removes it."""
    moment = datetime.datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=datetime.timezone.utc)
    kept, stripped = generalized_time(moment), generalized_time(moment.replace(microsecond=0))
    der_with_fraction = encoder.encode(useful.GeneralizedTime(kept)).hex()
    return (
        kept == "20260102030405.678Z" and stripped == "20260102030405Z" and not der_with_fraction.startswith("raises"),
        f"with microseconds {kept}, without {stripped}, the DER encoder accepts the fraction: {der_with_fraction}",
    )


def time_offset() -> tuple[bool, str]:
    """Measure fromDateTime for a naive time, for a time with an offset, and the DER encoding of the latter."""
    naive = datetime.datetime(2026, 1, 2, 3, 4, 5)
    local = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone(datetime.timedelta(hours=2)))
    in_utc = local.astimezone(datetime.timezone.utc)
    refused = der(useful.GeneralizedTime.fromDateTime(local))
    return (
        generalized_time(naive) == "20260102030405Z"
        and generalized_time(local) == "20260102030405+0200"
        and generalized_time(in_utc) == "20260102010405Z"
        and refused == "raises PyAsn1Error",
        f"naive {generalized_time(naive)}, +02:00 {generalized_time(local)}, in UTC {generalized_time(in_utc)}, "
        f"DER of the +02:00 time {refused}",
    )


add("GeneralizedTime.fromDateTime writes microseconds as a fraction; replace(microsecond=0) removes it", time_fraction)
add("GeneralizedTime.fromDateTime writes a naive time as Z and an offset as +HHMM; DER refuses the offset", time_offset)


# --- clone() and copy of structures that hold more than one level --------------------------------------------------


def filled_rdn_sequence(rdn_sequence: rfc5280.RDNSequence | None = None) -> rfc5280.RDNSequence:
    """Return `rdn_sequence` (default a new RDNSequence) with one RDN, commonName `a`."""
    value = rfc5280.RDNSequence() if rdn_sequence is None else rdn_sequence
    attribute = rfc5280.AttributeTypeAndValue()
    attribute["type"] = rfc5280.id_at_commonName
    attribute["value"] = b"\x0c\x01a"
    rdn = rfc5280.RelativeDistinguishedName()
    rdn.append(attribute)
    value.append(rdn)
    return value


def tagged_rdn_sequences() -> dict[str, rfc5280.RDNSequence]:
    """Return a filled RDNSequence untagged, with IMPLICIT [1] and with EXPLICIT [0]."""
    return {
        "untagged": filled_rdn_sequence(),
        "IMPLICIT [1]": filled_rdn_sequence(rfc5280.RDNSequence().subtype(implicitTag=IMPLICIT_1)),
        "EXPLICIT [0]": filled_rdn_sequence(rfc5280.RDNSequence().subtype(explicitTag=EXPLICIT_0)),
    }


def clone_with_values_of_name() -> tuple[bool, str]:
    """Measure clone(cloneValueFlag=True) of a filled RDNSequence, which is the content of every Name."""
    results = {name: raises(lambda v=v: v.clone(cloneValueFlag=True)) for name, v in tagged_rdn_sequences().items()}
    return all("tag-incompatible" in r for r in results.values()), "; ".join(f"{n}: {r}" for n, r in results.items())


def clone_with_values_of_name_holder() -> tuple[bool, str]:
    """Measure clone(cloneValueFlag=True) of structures that hold a filled Name."""
    general_name = rfc5280.GeneralName()
    general_name["directoryName"]["rdnSequence"] = filled_rdn_sequence()
    tbs_certificate = rfc5280.TBSCertificate()
    tbs_certificate["issuer"]["rdnSequence"] = filled_rdn_sequence()
    certificate = rfc5280.Certificate()
    certificate["tbsCertificate"]["issuer"]["rdnSequence"] = filled_rdn_sequence()
    results = {
        "GeneralName directoryName": raises(lambda: general_name.clone(cloneValueFlag=True)),
        "TBSCertificate issuer": raises(lambda: tbs_certificate.clone(cloneValueFlag=True)),
        "Certificate issuer": raises(lambda: certificate.clone(cloneValueFlag=True)),
    }
    return all("tag-incompatible" in r for r in results.values()), "; ".join(f"{n}: {r}" for n, r in results.items())


def clone_with_values_clones_constructed() -> tuple[bool, str]:
    """Measure that clone(cloneValueFlag=True) clones the constructed components and shares the simple ones."""
    spki = rfc5280.SubjectPublicKeyInfo()
    spki["algorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.840.10045.2.1")
    spki["subjectPublicKey"] = univ.BitString("1010")
    clone = spki.clone(cloneValueFlag=True)
    constructed_shared = clone["algorithm"] is spki["algorithm"]
    simple_shared = clone["algorithm"]["algorithm"] is spki["algorithm"]["algorithm"]
    clone["algorithm"]["algorithm"] = univ.ObjectIdentifier("1.3.101.112")
    original = str(spki["algorithm"]["algorithm"])
    sequence_of = univ.SequenceOf(componentType=rfc5280.AlgorithmIdentifier())
    sequence_of.append(sequences()["untagged"])
    element_shared = sequence_of.clone(cloneValueFlag=True)[0] is sequence_of[0]
    return (
        not constructed_shared and simple_shared and not element_shared and original == "1.2.840.10045.2.1",
        f"constructed component shared: {constructed_shared}, simple component shared: {simple_shared}, "
        f"SEQUENCE OF element shared: {element_shared}, original after the clone was changed: {original}",
    )


def copy_shares_component_list() -> tuple[bool, str]:
    """Measure that an assignment to a field of copy.copy(sequence) changes the original."""
    value = sequences()["untagged"]
    duplicate = copy.copy(value)
    duplicate["algorithm"] = univ.ObjectIdentifier("1.3.101.112")
    original = str(value["algorithm"])
    return original == "1.3.101.112", f"original after the copy was changed: {original}"


def clone_of_all_optional_and_of_sequence_of() -> tuple[bool, str]:
    """Measure the DER of clone() of a SEQUENCE with only OPTIONAL fields and of a filled SEQUENCE OF."""
    template = rfc4211.CertTemplate()
    template["version"] = 2
    tagged_template = rfc4211.CertTemplate().subtype(implicitTag=IMPLICIT_1)
    tagged_template["version"] = 2
    results = {
        "CertTemplate": template.clone(),
        "CertTemplate IMPLICIT [1]": tagged_template.clone(),
        **{f"RDNSequence {name}": value.clone() for name, value in tagged_rdn_sequences().items()},
    }
    ders = {name: der(value) for name, value in results.items()}
    expected = {
        "CertTemplate": "3000",
        "CertTemplate IMPLICIT [1]": "a100",
        "RDNSequence untagged": "3000",
        "RDNSequence IMPLICIT [1]": "a100",
        "RDNSequence EXPLICIT [0]": "a0023000",
    }
    return ders == expected, "; ".join(f"{name}: isValue {results[name].isValue}, DER {d}" for name, d in ders.items())


add(
    "clone(cloneValueFlag=True) of a filled RDNSequence raises PyAsn1Error, untagged, IMPLICIT and EXPLICIT",
    clone_with_values_of_name,
)
add(
    "clone(cloneValueFlag=True) raises for a GeneralName, a TBSCertificate and a Certificate that hold a filled Name",
    clone_with_values_of_name_holder,
)
add(
    "clone(cloneValueFlag=True) clones the constructed components again; only the simple components are shared",
    clone_with_values_clones_constructed,
)
add(
    "copy.copy of a SEQUENCE shares the component list: an assignment to a field of the copy changes the original",
    copy_shares_component_list,
)
add(
    "clone() of a SEQUENCE with only OPTIONAL fields and of a SEQUENCE OF encodes as an empty SEQUENCE",
    clone_of_all_optional_and_of_sequence_of,
)


def main() -> int:
    """Write every claim with its result; return 1 if one does not hold."""
    out = sys.stdout
    out.write(f"pyasn1 {pyasn1.__version__}, Python {sys.version.split()[0]}\n")
    failed = 0
    for number, (text, check) in enumerate(CLAIMS, start=1):
        try:
            holds, measured = check()
        except Exception as error:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            holds, measured = False, f"unexpected {type(error).__name__}: {str(error)[:80]}"
        failed += not holds
        out.write(f"{'HOLDS' if holds else 'FAILS'}  [{number}] {text}\n       {measured}\n")
    out.write(f"{len(CLAIMS) - failed} of {len(CLAIMS)} claims hold\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
