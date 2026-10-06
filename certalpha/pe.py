"""PE header parsing, Authenticode hashing and PE checksum (pure stdlib).

Static byte-level parsing only — no loader interaction, no execution.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Tuple

from .errors import CertAlphaError

DOS_MAGIC = 0x5A4D
PE_SIGNATURE = b"PE\x00\x00"
PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
CHECKSUM_OFFSET_IN_OPTIONAL = 64

MACHINE_NAMES = {
    0x014C: "i386",
    0x01C0: "arm",
    0x01C4: "armnt",
    0x0200: "ia64",
    0x8664: "amd64",
    0xAA64: "arm64",
}


@dataclass(frozen=True)
class PeImage:
    size: int
    e_lfanew: int
    coff_off: int
    opt_off: int
    size_of_optional_header: int
    pe32_plus: bool
    magic: int
    machine: int
    num_sections: int
    file_alignment: int
    checksum_off: int
    dd_base: int
    num_rva: int
    sec_entry_off: int  # absolute offset of Security data-directory entry, or -1
    cert_off: int       # file offset of certificate table (0 if none)
    cert_size: int      # size of certificate table (0 if none)

    @property
    def signed(self) -> bool:
        return self.cert_off > 0 and self.cert_size > 0

    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.machine, "0x%04X" % self.machine)

    @property
    def format_name(self) -> str:
        return "PE32+" if self.pe32_plus else "PE32"


def parse_pe(data: bytes) -> PeImage:
    """Parse the PE structures CertAlpha needs; raise CertAlphaError if invalid."""

    def fail(code: str, message: str, hint: str) -> None:
        raise CertAlphaError(code, message, hint)

    if len(data) < 0x40:
        fail(
            "BAD_PE",
            "file too small (%d bytes) for a DOS header" % len(data),
            "provide a valid PE image (.exe/.dll)",
        )
    if struct.unpack_from("<H", data, 0)[0] != DOS_MAGIC:
        fail(
            "BAD_PE",
            "missing MZ signature — not a PE image",
            "CertAlpha only processes PE files (.exe/.dll); raw .p7b input is accepted by 'inspect'",
        )

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        fail("BAD_PE", "e_lfanew out of range (0x%X)" % e_lfanew, "file corrupt or not PE")
    if data[e_lfanew : e_lfanew + 4] != PE_SIGNATURE:
        fail("BAD_PE", "missing PE signature at e_lfanew", "file corrupt or not PE")

    coff = e_lfanew + 4
    machine, num_sections, _ts, _sym, _nsym, opt_size, _ch = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt = coff + 20
    if opt_size < 96 or opt + opt_size > len(data):
        fail(
            "BAD_PE",
            "SizeOfOptionalHeader out of range (%d)" % opt_size,
            "optional header corrupt — rebuild the PE",
        )

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == PE32_MAGIC:
        pe32_plus = False
        num_rva_off = 92
        dd_base = 96
    elif magic == PE32PLUS_MAGIC:
        pe32_plus = True
        num_rva_off = 108
        dd_base = 112
    else:
        fail(
            "BAD_PE",
            "unknown optional header magic 0x%04X" % magic,
            "only PE32/PE32+ images are supported",
        )
        raise AssertionError  # unreachable; keeps type checkers happy

    checksum_off = opt + CHECKSUM_OFFSET_IN_OPTIONAL
    file_alignment = struct.unpack_from("<I", data, opt + 36)[0]
    if opt + num_rva_off + 4 <= opt + opt_size:
        num_rva = struct.unpack_from("<I", data, opt + num_rva_off)[0]
    else:
        num_rva = 0

    sec_entry_off = -1
    cert_off = 0
    cert_size = 0
    if num_rva >= 5:
        candidate = opt + dd_base + IMAGE_DIRECTORY_ENTRY_SECURITY * 8
        if candidate + 8 <= opt + opt_size and candidate + 8 <= len(data):
            sec_entry_off = candidate
            cert_off, cert_size = struct.unpack_from("<II", data, candidate)

    if cert_off and cert_off + cert_size > len(data):
        fail(
            "BAD_CERT_TABLE",
            "certificate table [%d..%d) exceeds file size %d"
            % (cert_off, cert_off + cert_size, len(data)),
            "file truncated after signing — restore it from a clean copy",
        )
    if cert_size and cert_off < sec_entry_off + 8:
        fail(
            "BAD_LAYOUT",
            "certificate table offset %d overlaps PE headers" % cert_off,
            "security directory entry is corrupt — rebuild the PE",
        )

    return PeImage(
        size=len(data),
        e_lfanew=e_lfanew,
        coff_off=coff,
        opt_off=opt,
        size_of_optional_header=opt_size,
        pe32_plus=pe32_plus,
        magic=magic,
        machine=machine,
        num_sections=num_sections,
        file_alignment=file_alignment,
        checksum_off=checksum_off,
        dd_base=dd_base,
        num_rva=num_rva,
        sec_entry_off=sec_entry_off,
        cert_off=cert_off,
        cert_size=cert_size,
    )


def write_security_directory(buf: bytearray, pe: PeImage, off: int, size: int) -> None:
    """Set IMAGE_DIRECTORY_ENTRY_SECURITY (VirtualAddress = file offset)."""
    if pe.sec_entry_off < 0:
        raise CertAlphaError(
            "NO_CERT_DIR",
            "PE has no Security data-directory slot (NumberOfRvaAndSizes=%d)" % pe.num_rva,
            "rebuild the target with a standard optional header (16 data directories)",
        )
    struct.pack_into("<II", buf, pe.sec_entry_off, off, size)


def authenticode_digest(data: bytes, pe: PeImage, algo: str) -> bytes:
    """Compute the Authenticode file digest.

    Excluded per spec: the PE CheckSum field, the Security data-directory
    entry, and the certificate table itself. Everything else is hashed in
    file order (the hash starts at offset 0).
    """
    try:
        hasher = hashlib.new(algo)
    except ValueError:
        raise CertAlphaError(
            "UNSUPPORTED_ALG",
            "hash algorithm '%s' unavailable in this Python build" % algo,
            "use a Python build with full OpenSSL algorithm support",
        )

    def segment(start: int, end: int, label: str) -> None:
        if start < 0 or end > len(data) or end < start:
            raise CertAlphaError(
                "BAD_LAYOUT",
                "invalid hash segment %s [%d..%d) vs file size %d"
                % (label, start, end, len(data)),
                "certificate table layout inconsistent — run 'strip' and retry",
            )
        if end > start:
            hasher.update(data[start:end])

    segment(0, pe.checksum_off, "start..checksum")
    if pe.sec_entry_off >= 0:
        segment(pe.checksum_off + 4, pe.sec_entry_off, "checksum..sec-dir")
        tail = pe.sec_entry_off + 8
        if pe.signed:
            segment(tail, pe.cert_off, "sec-dir..cert-table")
            tail = pe.cert_off + pe.cert_size
        segment(tail, len(data), "cert-table..EOF")
    else:
        segment(pe.checksum_off + 4, len(data), "checksum..EOF")
    return hasher.digest()


def compute_checksum(data: bytes, checksum_off: int) -> int:
    """Best-effort PE checksum (folded 16-bit word sum + file length).

    The 4-byte CheckSum field itself is excluded from the sum. This field is
    cosmetic for normal EXE/DLL files (the loader does not verify it); drivers
    (.sys) are the notable exception.
    """
    total = 0
    n = len(data)
    i = 0
    while i + 1 < n:
        if i == checksum_off:  # skip the 4-byte CheckSum field
            i += 4
            continue
        word = data[i] | (data[i + 1] << 8)
        total += word
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if i < n and not (checksum_off <= i < checksum_off + 4):
        total += data[i]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total += n
    return total & 0xFFFFFFFF
