"""High-level CertAlpha operations: extract / inject / strip / verify.

[Xyberix] — Cert Transplant Module — Requires Manual Execution.
No function here runs unless the operator invokes the CLI explicitly.
No process execution, no network access, no writes (I/O lives in cli.py).
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import pki
from . import pe as pemod
from .der import DerError
from .errors import CertAlphaError

WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


# --- certificate table primitives -----------------------------------------

def parse_certificate_table(table: bytes) -> List[bytes]:
    """Split a certificate table into raw WIN_CERTIFICATE entries (padding kept)."""
    entries: List[bytes] = []
    pos = 0
    while pos + 8 <= len(table):
        length, _revision, _ctype = struct.unpack_from("<IHH", table, pos)
        if length < 8:
            raise CertAlphaError(
                "BAD_CERT_TABLE",
                "WIN_CERTIFICATE.dwLength=%d < 8 at offset %d" % (length, pos),
                "certificate table corrupt — use 'strip' to remove it",
            )
        if pos + length > len(table):
            raise CertAlphaError(
                "BAD_CERT_TABLE",
                "WIN_CERTIFICATE at %d (length %d) overruns table (%d bytes)"
                % (pos, length, len(table)),
                "certificate table corrupt — use 'strip' to remove it",
            )
        entries.append(table[pos : pos + length])
        pos += length
    if pos < len(table) and any(table[pos:]):
        raise CertAlphaError(
            "BAD_CERT_TABLE",
            "%d non-zero trailing bytes after last certificate entry" % (len(table) - pos),
            "certificate table corrupt — use 'strip' to remove it",
        )
    return entries


def wrap_win_certificate(blob: bytes) -> bytes:
    """Wrap a PKCS#7 blob in a padded WIN_CERTIFICATE structure."""
    length = (8 + len(blob) + 7) & ~7
    entry = bytearray(length)
    struct.pack_into("<IHH", entry, 0, length, WIN_CERT_REVISION_2_0,
                     WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    entry[8 : 8 + len(blob)] = blob
    return bytes(entry)


def load_source_entries(src_data: bytes) -> List[bytes]:
    """Cert donor: a signed PE, or a raw PKCS#7 (.p7b/.der) blob."""
    if len(src_data) >= 2 and src_data[:2] == b"MZ":
        p = pemod.parse_pe(src_data)
        if not p.signed:
            raise CertAlphaError(
                "NO_SIGNATURE",
                "donor PE has no certificate table to copy",
                "use a signed donor PE, or pass a raw .p7b/.der as the source",
            )
        return parse_certificate_table(src_data[p.cert_off : p.cert_off + p.cert_size])
    # raw blob path: validate before wrapping
    pki.parse_signed_data(src_data)
    return [wrap_win_certificate(src_data)]


def extract_certificate_blobs(data: bytes) -> List[bytes]:
    """Return the bCertificate payload of each WIN_CERTIFICATE entry."""
    p = pemod.parse_pe(data)
    if not p.signed:
        raise CertAlphaError(
            "NO_SIGNATURE",
            "input PE is unsigned (no certificate table)",
            "supply a signed .exe/.dll as donor",
        )
    return [entry[8:] for entry in
            parse_certificate_table(data[p.cert_off : p.cert_off + p.cert_size])]


# --- operations ------------------------------------------------------------

def strip_signature(data: bytes, update_checksum: bool = False) -> bytes:
    """Remove the certificate table and clear the Security data directory."""
    p = pemod.parse_pe(data)
    if not p.signed:
        raise CertAlphaError(
            "NO_SIGNATURE",
            "file is already unsigned",
            "nothing to strip",
        )
    if p.cert_off + p.cert_size == len(data):
        out = data[: p.cert_off]
    else:
        # signature sits in the middle of the file: zero it in place
        ba = bytearray(data)
        for i in range(p.cert_off, p.cert_off + p.cert_size):
            ba[i] = 0
        out = bytes(ba)

    ba = bytearray(out)
    struct.pack_into("<II", ba, p.sec_entry_off, 0, 0)
    if update_checksum:
        struct.pack_into(
            "<I", ba, p.checksum_off, pemod.compute_checksum(bytes(ba), p.checksum_off)
        )
    return bytes(ba)


def inject_certificate(
    src_data: bytes,
    dst_data: bytes,
    mode: str = "replace",
    update_checksum: bool = False,
) -> bytes:
    """[Xyberix] — Cert Transplant Module — Requires Manual Execution

    Graft the donor's certificate table into the target PE.

    mode='replace': drop any existing target signature, append donor table.
    mode='append'  : keep the target's table and append the donor's as a
                     second WIN_CERTIFICATE entry (target must be EOF-signed).

    Result: the target carries the donor's signer string, but the Authenticode
    digest will NOT match (see verify). No execution of either input occurs.
    """
    if mode not in ("replace", "append"):
        raise CertAlphaError(
            "BAD_ARGUMENT",
            "unknown inject mode '%s'" % mode,
            "use --mode replace (default) or --mode append",
        )

    src_entries = load_source_entries(src_data)
    dst_pe = pemod.parse_pe(dst_data)

    if dst_pe.sec_entry_off < 0:
        raise CertAlphaError(
            "NO_CERT_DIR",
            "target PE has no Security data-directory slot "
            "(NumberOfRvaAndSizes=%d)" % dst_pe.num_rva,
            "rebuild the target with a standard optional header (16 data directories)",
        )

    if mode == "append" and dst_pe.signed:
        if dst_pe.cert_off + dst_pe.cert_size != len(dst_data):
            raise CertAlphaError(
                "UNSUPPORTED_LAYOUT",
                "target certificate table is not at end-of-file; append mode unsupported",
                "run 'strip' on the target first, then inject with --mode replace",
            )
        base = bytearray(dst_data)
        old_entries = parse_certificate_table(
            dst_data[dst_pe.cert_off : dst_pe.cert_off + dst_pe.cert_size]
        )
        table = b"".join(old_entries + src_entries)
        table_off = dst_pe.cert_off
    else:
        if dst_pe.signed and dst_pe.cert_off + dst_pe.cert_size == len(dst_data):
            base = bytearray(dst_data[: dst_pe.cert_off])
        elif dst_pe.signed:
            base = bytearray(dst_data)
            for i in range(dst_pe.cert_off, dst_pe.cert_off + dst_pe.cert_size):
                base[i] = 0
        else:
            base = bytearray(dst_data)

        pad = (8 - (len(base) % 8)) % 8
        if pad:
            base += b"\x00" * pad
        table = b"".join(src_entries)
        table_off = len(base)

    base += table
    pemod.write_security_directory(base, dst_pe, table_off, len(table))

    if update_checksum:
        struct.pack_into(
            "<I", base, dst_pe.checksum_off,
            pemod.compute_checksum(bytes(base), dst_pe.checksum_off),
        )
    return bytes(base)


def verify_signature(
    data: bytes, now: Optional[datetime] = None
) -> Dict[str, object]:
    """Offline Authenticode evaluation: parse the signature, compare digests.

    Deliberately does NOT evaluate chain trust (no trust-store or network
    access). Reports digest match/mismatch, signer identity and validity
    window only.
    """
    now = now or datetime.now(timezone.utc)
    p = pemod.parse_pe(data)
    result: Dict[str, object] = {
        "file_size": len(data),
        "format": p.format_name,
        "machine": p.machine_name,
        "signed": p.signed,
        "cert_table_offset": p.cert_off if p.signed else None,
        "cert_table_size": p.cert_size if p.signed else None,
        "certificate_count": 0,
        "certificate_types": [],
        "parseable": False,
        "chain_certificates": 0,
        "signer": None,
        "hash_algorithm": None,
        "expected_digest": None,
        "computed_digest": None,
        "digest_match": None,
        "page_hashes_present": False,
        "validity_window": None,
        "conclusion": "",
    }

    if not p.signed:
        result["conclusion"] = "No certificate table found — the file is unsigned."
        return result

    try:
        entries = parse_certificate_table(data[p.cert_off : p.cert_off + p.cert_size])
    except CertAlphaError as exc:
        result["conclusion"] = "Certificate table unreadable: %s" % exc.message
        return result

    result["certificate_count"] = len(entries)
    result["certificate_types"] = [
        "0x%04X" % struct.unpack_from("<IHH", e, 0)[2] for e in entries
    ]

    try:
        signed_data = pki.parse_signed_data(entries[0][8:])
    except CertAlphaError as exc:
        result["conclusion"] = "PKCS#7 unreadable: %s" % exc.message
        return result
    result["parseable"] = True

    certs, signers, content_info = pki.split_signed_data(signed_data)
    result["chain_certificates"] = max(len(certs) - 1, 0)

    serial = pki.signer_serial(signers)
    signer_der = pki.find_signer_cert(certs, serial) or (certs[0] if certs else None)
    if signer_der is not None:
        try:
            info = pki.cert_info(signer_der)
            result["signer"] = info
            nb = info.get("_not_before_dt")
            na = info.get("_not_after_dt")
            if isinstance(nb, datetime) and isinstance(na, datetime):
                if now > na:
                    result["validity_window"] = "expired"
                elif now < nb:
                    result["validity_window"] = "not-yet-valid"
                else:
                    result["validity_window"] = "ok"
        except (DerError, CertAlphaError) as exc:
            result["signer"] = None
            result["conclusion"] = "signer certificate unreadable: %s" % exc

    if content_info is not None:
        result["page_hashes_present"] = pki.page_hashes_present(content_info)
        digest = pki.spc_indirect_digest(content_info)
        if digest is not None:
            algo, expected = digest
            result["hash_algorithm"] = algo
            if expected:
                result["expected_digest"] = expected.hex()
            try:
                computed = pemod.authenticode_digest(data, p, algo)
                result["computed_digest"] = computed.hex()
                result["digest_match"] = computed == expected
            except CertAlphaError as exc:
                result["conclusion"] = "digest computation failed: %s" % exc.message

    if result["digest_match"] is True:
        result["conclusion"] = (
            "File digest matches the signer's stored digest (certificate table "
            "consistent). Chain trust to a trusted root is NOT evaluated offline "
            "— run 'signtool verify /pa' for a full check."
        )
    elif result["digest_match"] is False:
        extra = (
            " Page hashes are embedded, but the flat file digest still mismatches."
            if result["page_hashes_present"]
            else ""
        )
        result["conclusion"] = (
            "File digest MISMATCH — this file does NOT carry a cryptographically "
            "valid Authenticode signature. Expected after certificate "
            "transplantation or any post-signing modification: only naive checks "
            "(cert presence / parsed signer string) will be fooled; signtool, "
            "SmartScreen and driver loading will reject it.%s" % extra
        )
    elif not result["conclusion"]:
        if not result["parseable"]:
            result["conclusion"] = "Signature present but PKCS#7 could not be parsed."
        elif content_info is None:
            result["conclusion"] = (
                "PKCS#7 parsed but contains no Authenticode SPC digest — cannot "
                "evaluate file digest."
            )
        else:
            result["conclusion"] = "Digest could not be evaluated (see details)."

    return result
