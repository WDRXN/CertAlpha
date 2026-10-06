#!/usr/bin/env python3
"""CertAlpha self-test — synthetic fixtures only, fully offline.

Run:      python tests/selftest.py
Exit:     0 = all checks pass, 1 = failures

Everything here is built in memory (fake PE headers, synthetic X.509/PKCS#7).
No test executes any PE, opens a socket, or touches files outside a temp dir.
"""
from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certalpha import cli, ops, pki  # noqa: E402
from certalpha import der  # noqa: E402
from certalpha import pe as pemod  # noqa: E402
from certalpha.errors import CertAlphaError  # noqa: E402

FAILURES = []
CHECKS = [0]


def check(cond: bool, label: str) -> None:
    CHECKS[0] += 1
    if cond:
        print("  PASS  %s" % label)
    else:
        print("  FAIL  %s" % label)
        FAILURES.append(label)


def section(name: str) -> None:
    print("\n== %s ==" % name)


# --- tiny DER encoder (test-only) -----------------------------------------

def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + length + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def oid(dotted: str) -> bytes:
    arcs = [int(x) for x in dotted.split(".")]
    first = 40 * arcs[0] + arcs[1]
    body = bytearray([first & 0x7F])
    first >>= 7
    while first:
        body.insert(0, 0x80 | (first & 0x7F))
        first >>= 7
    for arc in arcs[2:]:
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunks))
    return tlv(0x06, bytes(body))


def integer(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return tlv(0x02, raw)


def rdns(*pairs) -> bytes:
    return seq(
        *[
            set_(seq(oid(o), tlv(0x13, v.encode("ascii"))))
            for o, v in pairs
        ]
    )


def wrap_entry(blob: bytes) -> bytes:
    length = (8 + len(blob) + 7) & ~7
    entry = bytearray(length)
    struct.pack_into("<IHH", entry, 0, length, 0x0200, 0x0002)
    entry[8 : 8 + len(blob)] = blob
    return bytes(entry)


# --- synthetic PE builder --------------------------------------------------

def make_pe(pe32_plus: bool = False, cert_blob=None) -> bytes:
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    opt_size = 240 if pe32_plus else 224
    coff = struct.pack(
        "<HHIIIHH",
        0x8664 if pe32_plus else 0x014C,  # machine
        1,                                # sections
        0, 0, 0,                          # timestamp/symtab/symbols
        opt_size,
        0x0102,                           # characteristics
    )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32_plus else 0x10B)  # magic
    struct.pack_into("<I", opt, 16, 0x1000)   # entry point
    struct.pack_into("<I", opt, 20, 0x1000)   # base of code
    if pe32_plus:
        dd_base = 112
        struct.pack_into("<Q", opt, 24, 0x140000000)  # image base
        struct.pack_into("<Q", opt, 72, 0x100000)      # stack reserve
        struct.pack_into("<Q", opt, 80, 0x1000)        # stack commit
        struct.pack_into("<Q", opt, 88, 0x100000)      # heap reserve
        struct.pack_into("<Q", opt, 96, 0x1000)        # heap commit
        struct.pack_into("<I", opt, 104, 0)            # loader flags
        struct.pack_into("<I", opt, 108, 16)           # number of data dirs
    else:
        dd_base = 96
        struct.pack_into("<I", opt, 24, 0)             # base of data
        struct.pack_into("<I", opt, 28, 0x400000)      # image base
        struct.pack_into("<I", opt, 72, 0x100000)
        struct.pack_into("<I", opt, 76, 0x1000)
        struct.pack_into("<I", opt, 80, 0x100000)
        struct.pack_into("<I", opt, 84, 0x1000)
        struct.pack_into("<I", opt, 88, 0)
        struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<I", opt, 32, 0x1000)  # section alignment
    struct.pack_into("<I", opt, 36, 0x200)   # file alignment
    struct.pack_into("<I", opt, 56, 0x2000)  # size of image
    struct.pack_into("<I", opt, 60, 0x200)   # size of headers
    struct.pack_into("<H", opt, 68, 3)       # subsystem (console)

    entry = b""
    if cert_blob is not None:
        entry = wrap_entry(cert_blob)
        struct.pack_into("<II", opt, dd_base + 4 * 8, 0x400, len(entry))

    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<I", sec, 8, 0x100)      # virtual size
    struct.pack_into("<I", sec, 12, 0x1000)    # virtual address
    struct.pack_into("<I", sec, 16, 0x200)     # raw size
    struct.pack_into("<I", sec, 20, 0x200)     # raw pointer
    struct.pack_into("<I", sec, 36, 0x60000020)

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec)
    if len(headers) > 0x200:
        raise AssertionError("test PE headers exceed SizeOfHeaders")
    headers = headers + b"\x00" * (0x200 - len(headers))
    body = headers + (b"\x90" * 0x200)  # section raw data
    return body + entry


# --- synthetic X.509 / PKCS#7 ---------------------------------------------

SERIAL = 0x0102A3B4C5D6


def make_certificate() -> bytes:
    modulus = (1 << 2047) + 12345  # 2048-bit modulus
    sig_alg = seq(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    issuer = rdns(("2.5.4.10", "Xyberix Lab"))
    subject = rdns(
        ("2.5.4.3", "CertAlpha Test Signer"),
        ("2.5.4.10", "Xyberix Lab"),
    )
    validity = seq(tlv(0x17, b"240101000000Z"), tlv(0x17, b"270101000000Z"))
    spki = seq(
        seq(oid("1.2.840.113549.1.1.1"), tlv(0x05, b"")),
        tlv(0x03, b"\x00" + seq(integer(modulus), integer(65537))),
    )
    tbs = seq(
        tlv(0xA0, integer(2)),   # version v3
        integer(SERIAL),
        sig_alg,
        issuer,
        validity,
        subject,
        spki,
    )
    return seq(tbs, sig_alg, tlv(0x03, b"\x00" + b"\xAA" * 32))


def make_pkcs7(cert: bytes, digest_algo_oid: str, expected_digest: bytes) -> bytes:
    spc = seq(
        seq(oid("1.3.6.1.4.1.311.2.1.15")),                     # SpcPeImageData
        seq(
            seq(oid(digest_algo_oid), tlv(0x05, b"")),          # DigestInfo.alg
            tlv(0x04, expected_digest),                         # file digest
        ),
    )
    content_info = seq(oid("1.3.6.1.4.1.311.2.1.4"), tlv(0xA0, spc))
    digest_algs = set_(seq(oid(digest_algo_oid)))
    certs = tlv(0xA0, cert)
    signer_info = seq(
        integer(1),
        seq(rdns(("2.5.4.10", "Xyberix Lab")), integer(SERIAL)),
        seq(oid(digest_algo_oid)),
        seq(oid("1.2.840.113549.1.1.1")),
        tlv(0x03, b"\x00" + b"\xBB" * 32),
    )
    signed_data = seq(integer(3), digest_algs, content_info, certs, set_(signer_info))
    return seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, signed_data))


# --- checks ----------------------------------------------------------------

def main() -> int:
    section("DER round-trip")
    o = oid("1.2.840.113549.1.7.2")
    node, end = der.parse_der(o, 0)
    check(der.decode_oid(node) == "1.2.840.113549.1.7.2", "OID round-trip")
    check(end == len(o), "OID consumes all bytes")
    nested = seq(integer(7), oid("2.5.4.3"), tlv(0x13, b"hello"))
    n, _ = der.parse_der(nested, 0)
    kids = n.child_list()
    check(len(kids) == 3, "nested SEQUENCE child count")
    check(der.decode_integer(kids[0]) == 7, "INTEGER decode")
    check(der.decode_string(kids[2]) == "hello", "PrintableString decode")

    section("PE parsing (PE32 / PE32+)")
    for plus in (False, True):
        raw = make_pe(plus)
        p = pemod.parse_pe(raw)
        check(p.pe32_plus == plus, "%s format flag" % p.format_name)
        check(p.checksum_off == p.opt_off + 64, "%s checksum field offset" % p.format_name)
        check(not p.signed, "%s unsigned by default" % p.format_name)
        d = pemod.authenticode_digest(raw, p, "sha256")
        check(len(d) == 32, "%s authenticode digest length" % p.format_name)
        c1 = pemod.compute_checksum(raw, p.checksum_off)
        c2 = pemod.compute_checksum(raw, p.checksum_off)
        check(c1 == c2, "%s checksum deterministic" % p.format_name)
        mutated = bytearray(raw)
        mutated[0x300] ^= 0xFF
        c3 = pemod.compute_checksum(bytes(mutated), p.checksum_off)
        check(c3 != c1, "%s checksum reacts to content change" % p.format_name)

    section("extract")
    donor_blob = b"FAKE-P7B-" * 16
    donor = make_pe(cert_blob=donor_blob)
    pd = pemod.parse_pe(donor)
    check(pd.signed, "donor reports signed")
    check(pd.cert_off == 0x400, "donor certificate table at EOF (0x400)")
    check(len(ops.extract_certificate_blobs(donor)) == 1, "one certificate blob")
    check(ops.extract_certificate_blobs(donor)[0] == donor_blob, "extracted payload matches donor")

    section("inject (replace)")
    target = make_pe()
    out = ops.inject_certificate(donor, target)
    pt = pemod.parse_pe(out)
    check(pt.signed, "target becomes signed")
    check(pt.cert_off == 0x400 and pt.cert_off % 8 == 0, "transplant offset 8-byte aligned")
    # only the 8-byte security data-directory entry may change in the header/body
    d = pt.sec_entry_off
    preserved = out[:d] == target[:d] and out[d + 8 : 0x400] == target[d + 8 : 0x400]
    check(preserved, "target bytes preserved except security dir entry")
    entries = ops.parse_certificate_table(out[pt.cert_off : pt.cert_off + pt.cert_size])
    check(len(entries) == 1, "single WIN_CERTIFICATE entry")
    check(entries[0][8:] == donor_blob, "grafted payload equals donor blob")

    section("strip round-trip")
    stripped = ops.strip_signature(out)
    check(stripped == target, "strip restores exact original bytes")
    check(not pemod.parse_pe(stripped).signed, "stripped file reports unsigned")
    try:
        ops.strip_signature(stripped)
        check(False, "strip on unsigned raises NO_SIGNATURE")
    except CertAlphaError as exc:
        check(exc.code == "NO_SIGNATURE", "strip on unsigned raises NO_SIGNATURE")

    section("inject (append / replace on signed target)")
    target2 = make_pe(cert_blob=b"ORIGINAL-BLOB-8B")
    out2 = ops.inject_certificate(donor, target2, mode="append")
    p2 = pemod.parse_pe(out2)
    check(p2.cert_off == 0x400, "append keeps original table offset")
    entries2 = ops.parse_certificate_table(out2[p2.cert_off : p2.cert_off + p2.cert_size])
    check(len(entries2) == 2, "append yields two certificate entries")
    check(entries2[0][8:].startswith(b"ORIGINAL-BLOB-8B"), "original entry preserved")
    check(entries2[1][8:].startswith(b"FAKE-P7B-"), "donor entry appended")

    out3 = ops.inject_certificate(donor, target2, mode="replace")
    p3 = pemod.parse_pe(out3)
    entries3 = ops.parse_certificate_table(out3[p3.cert_off : p3.cert_off + p3.cert_size])
    check(len(entries3) == 1, "replace drops old table")
    check(entries3[0][8:].startswith(b"FAKE-P7B-"), "replace keeps donor entry")

    out4 = ops.inject_certificate(donor, make_pe(pe32_plus=True))
    check(pemod.parse_pe(out4).signed, "inject into PE32+ target")

    section("X.509 parsing (synthetic certificate)")
    cert = make_certificate()
    cnode, _ = der.parse_der(cert, 0)
    info = pki.cert_info(cnode)
    check(info["subject"] == "CN=CertAlpha Test Signer, O=Xyberix Lab", "subject RDN order")
    check(info["issuer"] == "O=Xyberix Lab", "issuer RDN")
    check(info["serial"] == "01:02:A3:B4:C5:D6", "serial formatting")
    check(info["key_algorithm"] == "RSA-2048", "RSA key size detection")
    check(str(info["not_before"]).startswith("2024-01-01"), "notBefore decoded")
    check(str(info["not_after"]).startswith("2027-01-01"), "notAfter decoded")
    check(info["signature_algorithm"] == "sha256WithRSAEncryption", "signature algorithm map")

    section("PKCS#7 parsing (synthetic Authenticode blob)")
    good_digest = pemod.authenticode_digest(make_pe(), pemod.parse_pe(make_pe()), "sha256")
    p7b_good = make_pkcs7(cert, "2.16.840.1.101.3.4.2.1", good_digest)
    sd = pki.parse_signed_data(p7b_good)
    certs_bag, signers, content_info = pki.split_signed_data(sd)
    check(len(certs_bag) == 1, "certificate bag size")
    serial = pki.signer_serial(signers)
    check(serial is not None, "signer serial extracted")
    signer = pki.find_signer_cert(certs_bag, serial)
    check(signer is not None, "signer certificate matched by serial")
    check(content_info is not None, "contentInfo located")
    got = pki.spc_indirect_digest(content_info)
    check(got is not None and got[0] == "sha256", "SPC digest algorithm resolved")
    check(got is not None and got[1] == good_digest, "SPC expected digest recovered")
    check(not pki.page_hashes_present(content_info), "no page hashes in synthetic blob")

    section("verify (digest match / mismatch)")
    unsigned = make_pe()
    good = pemod.authenticode_digest(unsigned, pemod.parse_pe(unsigned), "sha256")
    donor_good = make_pe(cert_blob=make_pkcs7(cert, "2.16.840.1.101.3.4.2.1", good))
    out_good = ops.inject_certificate(donor_good, unsigned)
    st = ops.verify_signature(out_good)
    check(st["signed"] is True, "verify: reports signed")
    check(st["parseable"] is True, "verify: PKCS#7 parseable")
    check(st["digest_match"] is True, "verify: digest MATCH after inject")
    check(st["validity_window"] == "ok", "verify: validity window ok")
    check(
        isinstance(st["signer"], dict)
        and st["signer"]["subject"] == "CN=CertAlpha Test Signer",
        "verify: signer identity resolved",
    )
    check(st["hash_algorithm"] == "sha256", "verify: hash algorithm reported")

    p7b_bad = make_pkcs7(cert, "2.16.840.1.101.3.4.2.1", b"\x00" * 32)
    donor_bad = make_pe(cert_blob=p7b_bad)
    st_bad = ops.verify_signature(ops.inject_certificate(donor_bad, unsigned))
    check(st_bad["digest_match"] is False, "verify: wrong digest MISMATCH")
    check("MISMATCH" in str(st_bad["conclusion"]), "verify: mismatch conclusion text")
    check(
        ops.verify_signature(make_pe())["signed"] is False,
        "verify: unsigned target reported unsigned",
    )

    section("raw PKCS#7 donor + error contract")
    entries_raw = ops.load_source_entries(p7b_good)
    check(
        len(entries_raw) == 1 and entries_raw[0][8:].startswith(b"\x30"),
        "raw .p7b donor wrapped in WIN_CERTIFICATE",
    )
    check(
        pemod.parse_pe(ops.inject_certificate(p7b_good, make_pe())).signed,
        "raw .p7b donor injects",
    )
    try:
        ops.extract_certificate_blobs(unsigned)
        check(False, "extract unsigned raises NO_SIGNATURE")
    except CertAlphaError as exc:
        check(exc.code == "NO_SIGNATURE", "extract unsigned raises NO_SIGNATURE")
    try:
        ops.parse_certificate_table(b"\x04\x00\x00\x00\x02\x00\x02\x00")
        check(False, "corrupt table raises BAD_CERT_TABLE")
    except CertAlphaError as exc:
        check(exc.code == "BAD_CERT_TABLE", "corrupt table raises BAD_CERT_TABLE")
    try:
        ops.inject_certificate(b"MZ-not-a-pe", target)
        check(False, "bad donor raises structured error")
    except CertAlphaError as exc:
        check(
            exc.code in ("BAD_PE", "PKCS7_PARSE"),
            "bad donor raises structured error (%s)" % exc.code,
        )
        check(bool(exc.suggestion), "error carries a suggestion")

    section("CLI smoke (temp dir)")
    tmp = tempfile.mkdtemp(prefix="certalpha_selftest_")
    try:
        src_path = os.path.join(tmp, "donor.exe")
        dst_path = os.path.join(tmp, "target.dll")
        out_path = os.path.join(tmp, "out.dll")
        with open(src_path, "wb") as fh:
            fh.write(donor_good)
        with open(dst_path, "wb") as fh:
            fh.write(make_pe(pe32_plus=True))

        check(cli.main(["info", src_path]) == 0, "cli info -> 0")
        check(cli.main(["inspect", src_path]) == 0, "cli inspect -> 0")
        check(cli.main(["verify", src_path]) == 0, "cli verify -> 0")
        check(
            cli.main(["inject", src_path, dst_path, "-o", out_path]) == 2,
            "cli inject WITHOUT --ack-authorized refused (exit 2)",
        )
        check(
            cli.main(
                ["inject", src_path, dst_path, "-o", out_path, "--ack-authorized"]
            )
            == 0,
            "cli inject WITH --ack-authorized -> 0",
        )
        check(cli.main(["verify", out_path, "--json"]) == 0, "cli verify --json -> 0")

        ext_dir = os.path.join(tmp, "extracted")
        check(
            cli.main(["extract", src_path, "-o", ext_dir]) == 0,
            "cli extract -> 0",
        )
        produced = os.path.join(ext_dir, "donor.cert1.p7b")
        check(os.path.isfile(produced), "extract wrote .p7b file")
        if os.path.isfile(produced):
            with open(produced, "rb") as fh:
                blob = fh.read()
            check(
                pemod.parse_pe(
                    ops.inject_certificate(blob, make_pe())
                ).signed,
                "extracted .p7b can be re-injected as donor",
            )
        strip_out = os.path.join(tmp, "out.unsigned.dll")
        check(
            cli.main(["strip", out_path, "-o", strip_out]) == 0,
            "cli strip -> 0",
        )
        check(
            not pemod.parse_pe(open(strip_out, "rb").read()).signed,
            "stripped output is unsigned",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n%d checks, %d failed" % (CHECKS[0], len(FAILURES)))
    if FAILURES:
        for label in FAILURES:
            print("  FAILED: %s" % label)
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
