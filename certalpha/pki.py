"""PKCS#7 (Authenticode) and X.509 certificate parsing — pure stdlib, static.

No process execution, no network access, no trust-store lookups: this module
only interprets bytes that were handed to it.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set, Tuple

from .der import (
    DerError,
    DerNode,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_SET,
    decode_bitstring,
    decode_integer,
    decode_oid,
    decode_string,
    decode_time,
    parse_der,
)
from .errors import CertAlphaError

# --- well-known OIDs -------------------------------------------------------
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
SPC_PE_IMAGE_OID = "1.3.6.1.4.1.311.2.1.15"
PAGE_HASH_V1_OID = "1.3.6.1.4.1.311.2.3.1"
PAGE_HASH_V2_OID = "1.3.6.1.4.1.311.2.3.2"
PAGE_HASH_OIDS: Set[str] = {PAGE_HASH_V1_OID, PAGE_HASH_V2_OID}

HASH_OIDS: Dict[str, str] = {
    "1.3.14.3.2.26": "sha1",
    "1.2.840.113549.2.5": "md5",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

SIG_ALG_OIDS: Dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
}

NAME_ATTR_OIDS: Dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.3.6.1.4.1.311.20.2.3": "UPN",
}

CURVE_OIDS: Dict[str, str] = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
}

EDDSA_OIDS: Dict[str, str] = {
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


def _pkcs7_error(message: str, suggestion: str) -> CertAlphaError:
    return CertAlphaError("PKCS7_PARSE", message, suggestion)


# --- PKCS#7 SignedData -----------------------------------------------------

def parse_signed_data(p7: bytes) -> DerNode:
    """Parse a PKCS#7/CMS ContentInfo and return the inner SignedData SEQUENCE."""
    try:
        root, _ = parse_der(p7, 0)
    except DerError as exc:
        raise _pkcs7_error(
            "input is not valid DER: %s" % exc,
            "supply a signed PE or an Authenticode .p7b/.der blob",
        )
    if not (root.is_universal and root.tag == TAG_SEQUENCE):
        raise _pkcs7_error(
            "top-level element is not a ContentInfo SEQUENCE",
            "input is not a PKCS#7 object",
        )
    kids = root.child_list()
    if not kids or not (kids[0].is_universal and kids[0].tag == TAG_OID):
        raise _pkcs7_error("ContentInfo has no contentType", "input is not PKCS#7")
    content_type = decode_oid(kids[0])
    if content_type != SIGNED_DATA_OID:
        raise _pkcs7_error(
            "unexpected PKCS#7 content type %s (expected signedData)" % content_type,
            "only PKCS#7 SignedData objects are supported",
        )
    if len(kids) < 2:
        raise _pkcs7_error("ContentInfo carries no signedData content", "blob incomplete")
    ctx = kids[1]
    inner = ctx.child_list()
    if not inner or not (inner[0].is_universal and inner[0].tag == TAG_SEQUENCE):
        raise _pkcs7_error("signedData content is missing or malformed", "blob corrupt")
    return inner[0]


def split_signed_data(
    sd: DerNode,
) -> Tuple[List[DerNode], List[DerNode], Optional[DerNode]]:
    """Split SignedData into (certificates, signerInfos, contentInfo)."""
    certs: List[DerNode] = []
    signers: List[DerNode] = []
    content_info: Optional[DerNode] = None
    for child in sd.children():
        if child.is_universal and child.tag == TAG_SET:
            if content_info is None:
                continue  # digestAlgorithms SET — not needed here
            signers.extend(child.children())
        elif child.is_universal and child.tag == TAG_SEQUENCE and content_info is None:
            content_info = child
        elif child.is_context and child.tag == 0:
            certs.extend(_unwrap_certificates(child))
    return certs, signers, content_info


def _unwrap_certificates(node: DerNode) -> List[DerNode]:
    """certificates [0] IMPLICIT SET OF Certificate — tolerate one extra SET level."""
    out: List[DerNode] = []
    for child in node.children():
        if child.is_universal and child.tag == TAG_SET:
            out.extend(child.children())
        else:
            out.append(child)
    return out


def signer_serial(signers: List[DerNode]) -> Optional[bytes]:
    """Extract the signer certificate serial number from the first SignerInfo."""
    for si in signers:
        kids = si.child_list()
        for cand in kids[1:4]:
            if not (cand.is_universal and cand.tag == TAG_SEQUENCE):
                continue
            sub = cand.child_list()
            if len(sub) < 2:
                continue
            if sub[0].is_universal and sub[0].tag == TAG_SEQUENCE and (
                sub[-1].is_universal and sub[-1].tag == TAG_INTEGER
            ):
                return sub[-1].content
    return None


def _normalize_serial(raw: bytes) -> bytes:
    stripped = raw.lstrip(b"\x00")
    return stripped or b"\x00"


def find_signer_cert(
    certs: List[DerNode], serial: Optional[bytes]
) -> Optional[DerNode]:
    """Locate the signer certificate inside the PKCS#7 certificate bag."""
    if serial is None:
        return None
    wanted = _normalize_serial(serial)
    for cert in certs:
        try:
            info = cert_info(cert)
        except (DerError, CertAlphaError):
            continue
        try:
            cert_serial = bytes.fromhex(info["serial"].replace(":", ""))
        except ValueError:
            continue
        if _normalize_serial(cert_serial) == wanted:
            return cert
    return None


def spc_indirect_digest(content_info: DerNode) -> Optional[Tuple[str, bytes]]:
    """Pull (hash-algorithm, expected file digest) out of SpcIndirectDataContent."""
    kids = content_info.child_list()
    if len(kids) < 2:
        return None
    if not (kids[0].is_universal and kids[0].tag == TAG_OID):
        return None
    ctx = kids[1]
    inner = ctx.child_list()
    if not inner:
        return None
    spc = inner[0]
    if not (spc.is_universal and spc.tag == TAG_SEQUENCE):
        return None
    seqs = [c for c in spc.children() if c.is_universal and c.tag == TAG_SEQUENCE]
    if len(seqs) < 2:
        return None
    digest_info = seqs[-1]  # data SEQUENCE comes first, DigestInfo last
    dik = digest_info.child_list()
    if len(dik) < 2:
        return None
    alg_kids = dik[0].child_list()
    if not alg_kids:
        return None
    try:
        oid = decode_oid(alg_kids[0])
    except DerError:
        return None
    if dik[1].tag != TAG_OCTET_STRING:
        return None
    return HASH_OIDS.get(oid, oid), dik[1].content


def content_type_oid(content_info: DerNode) -> Optional[str]:
    kids = content_info.child_list()
    if not kids:
        return None
    try:
        return decode_oid(kids[0])
    except DerError:
        return None


def page_hashes_present(content_info: DerNode) -> bool:
    """True if the SPC payload embeds page-hash OIDs (incremental signing)."""
    return _contains_oid(content_info, PAGE_HASH_OIDS)


def _contains_oid(node: DerNode, wanted: Set[str]) -> bool:
    if node.is_universal and node.tag == TAG_OID:
        try:
            return decode_oid(node) in wanted
        except DerError:
            return False
    if node.constructed:
        return any(_contains_oid(child, wanted) for child in node.children())
    return False


# --- X.509 -----------------------------------------------------------------

def colon_hex(raw: bytes) -> str:
    h = raw.hex().upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


def name_to_string(node: DerNode) -> str:
    """RDNSequence -> 'CN=..., O=..., C=...' (encoding order preserved)."""
    parts: List[str] = []
    for rdn in node.children():
        if not (rdn.is_universal and rdn.tag == TAG_SET):
            continue
        attrs: List[str] = []
        for atv in rdn.children():
            if not (atv.is_universal and atv.tag == TAG_SEQUENCE):
                continue
            sub = atv.child_list()
            if len(sub) < 2:
                continue
            try:
                oid = decode_oid(sub[0])
            except DerError:
                continue
            label = NAME_ATTR_OIDS.get(oid, oid)
            try:
                value = decode_string(sub[1])
            except DerError:
                value = sub[1].content.hex()
            attrs.append("%s=%s" % (label, value))
        if attrs:
            parts.append("+".join(attrs))
    return ", ".join(parts)


def _key_info(spki: DerNode) -> Tuple[str, Optional[int]]:
    """SPKI -> (human key label, key size in bits or None)."""
    kids = spki.child_list()
    if not kids:
        return "unknown", None
    alg = kids[0].child_list()
    if not alg:
        return "unknown", None
    try:
        alg_oid = decode_oid(alg[0])
    except DerError:
        return "unknown", None

    if alg_oid == "1.2.840.113549.1.1.1":  # rsaEncryption
        if len(kids) < 2:
            return "RSA", None
        try:
            payload = decode_bitstring(kids[1])
            pub, _ = parse_der(payload, 0)
            fields = pub.child_list()
            modulus = decode_integer(fields[0])
            return "RSA-%d" % modulus.bit_length(), modulus.bit_length()
        except (DerError, IndexError):
            return "RSA", None

    if alg_oid == "1.2.840.10045.2.1":  # ecPublicKey
        if len(alg) > 1 and alg[1].is_universal and alg[1].tag == TAG_OID:
            try:
                curve = decode_oid(alg[1])
            except DerError:
                curve = ""
            label = CURVE_OIDS.get(curve, curve or "EC")
        else:
            label = "EC"
        bits = {"P-256": 256, "P-384": 384, "P-521": 521}.get(label)
        return label, bits

    if alg_oid in EDDSA_OIDS:
        return EDDSA_OIDS[alg_oid], None

    return alg_oid, None


def cert_info(cert: DerNode) -> Dict[str, object]:
    """Summarise an X.509 certificate as a plain dict.

    Keys prefixed with ``_`` are helper values (datetime objects) intended for
    in-process consumers; they are dropped from JSON output.
    """
    kids = cert.child_list()
    if len(kids) < 3 or not (kids[0].is_universal and kids[0].tag == TAG_SEQUENCE):
        raise DerError("not an X.509 Certificate SEQUENCE")
    tbs = kids[0]
    sig_alg_node = kids[1]

    tk = tbs.child_list()
    idx = 0
    version: Optional[int] = None
    if tk and tk[0].is_context and tk[0].tag == 0:
        vsub = tk[0].child_list()
        if vsub and vsub[0].is_universal and vsub[0].tag == TAG_INTEGER:
            version = decode_integer(vsub[0]) + 1
        idx = 1
    if len(tk) < idx + 6:
        raise DerError("truncated TBSCertificate")

    serial_node = tk[idx]
    issuer_node = tk[idx + 2]
    validity_node = tk[idx + 3]
    subject_node = tk[idx + 4]
    spki_node = tk[idx + 5]

    serial_hex = serial_node.content.hex().upper()
    serial_fmt = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))

    vk = validity_node.child_list()
    not_before_raw = vk[0].content.decode("ascii", "replace") if vk else ""
    not_after_raw = vk[1].content.decode("ascii", "replace") if len(vk) > 1 else ""
    not_before = decode_time(vk[0]) if vk else None
    not_after = decode_time(vk[1]) if len(vk) > 1 else None

    try:
        sig_alg = decode_oid(sig_alg_node.child_list()[0])
    except (DerError, IndexError):
        sig_alg = "unknown"

    key_label, key_bits = _key_info(spki_node)
    raw = cert.raw

    return {
        "subject": name_to_string(subject_node),
        "issuer": name_to_string(issuer_node),
        "serial": serial_fmt,
        "version": version,
        "not_before": not_before.isoformat() if not_before else not_before_raw,
        "not_after": not_after.isoformat() if not_after else not_after_raw,
        "signature_algorithm": SIG_ALG_OIDS.get(sig_alg, sig_alg),
        "key_algorithm": key_label,
        "key_size_bits": key_bits,
        "sha1": colon_hex(hashlib.sha1(raw).digest()),
        "sha256": colon_hex(hashlib.sha256(raw).digest()),
        "der_size": len(raw),
        "_not_before_dt": not_before,
        "_not_after_dt": not_after,
    }
