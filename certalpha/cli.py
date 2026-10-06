"""CertAlpha command-line interface. Operator-triggered only; no auto-exec.

No subprocess calls, no sockets — this module reads files you name and writes
files you name, then prints a report.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __appname__, __version__
from . import ops, pki
from . import pe as pemod
from .errors import CertAlphaError

EPILOG = """examples:
  certalpha info   {{TARGET_PE}}
  certalpha extract {{DONOR_PE}} -o ./extracted
  certalpha inspect {{DONOR_PE}}
  certalpha verify  {{TARGET_PE}}
  certalpha strip   {{TARGET_PE}} -o {{TARGET_PE}}.unsigned.exe
  certalpha inject  {{DONOR_PE}} {{TARGET_PE}} -o {{OUTPUT_PE}} --ack-authorized

exit codes:
  0 success | 1 unexpected internal error path (reserved) | 2 operational error
"""

ACK_TEXT = (
    "risk gate: transplanting an Authenticode certificate from one binary into "
    "another is a signature-spoofing operation (only naive signature checks can "
    "be fooled — the graft is never cryptographically valid). Use solely on "
    "binaries and systems you are authorized to test."
)


# --- small helpers ---------------------------------------------------------

def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: _jsonable(v)
            for k, v in obj.items()
            if not (isinstance(k, str) and k.startswith("_"))
        }
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, _dt.datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    return obj


def _emit(args: argparse.Namespace, payload: Dict[str, Any], lines: List[str]) -> None:
    if getattr(args, "json", False):
        print(json.dumps(_jsonable(payload), indent=2, default=str))
    else:
        for line in lines:
            print(line)


def _read_file(path: str) -> bytes:
    if not os.path.isfile(path):
        raise CertAlphaError(
            "FILE_NOT_FOUND",
            "input file not found: %s" % path,
            "check the path and try again",
        )
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise CertAlphaError("IO_ERROR", str(exc), "check file permissions")


def _guard_distinct_paths(in_path: str, out_path: str, force: bool) -> None:
    if os.path.abspath(in_path) == os.path.abspath(out_path) and not force:
        raise CertAlphaError(
            "SAME_PATH",
            "output path equals input path (in-place modification)",
            "choose a different -o path, or pass --force to modify in place",
        )


def _write_file(path: str, data: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    try:
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        raise CertAlphaError("IO_ERROR", str(exc), "check path and permissions")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validity_label(info: Dict[str, Any]) -> str:
    nb, na = info.get("_not_before_dt"), info.get("_not_after_dt")
    window = "unknown"
    if isinstance(nb, _dt.datetime) and isinstance(na, _dt.datetime):
        now = _dt.datetime.now(_dt.timezone.utc)
        if now > na:
            window = "EXPIRED"
        elif now < nb:
            window = "not yet valid"
        else:
            window = "valid"
    return "%s (%s .. %s)" % (window, info.get("not_before"), info.get("not_after"))


# --- commands --------------------------------------------------------------

def _cmd_info(args: argparse.Namespace) -> int:
    data = _read_file(args.input)
    p = pemod.parse_pe(data)
    lines = [
        "file       : %s" % args.input,
        "size       : %d bytes" % len(data),
        "sha256     : %s" % _sha256(data),
        "format     : %s" % p.format_name,
        "machine    : %s" % p.machine_name,
        "sections   : %d" % p.num_sections,
        "file align : 0x%X" % p.file_alignment,
        "signed     : %s" % ("yes" if p.signed else "no"),
    ]
    if p.signed:
        lines.append(
            "cert table : offset=0x%X size=%d" % (p.cert_off, p.cert_size)
        )
    payload = {
        "status": "OK",
        "command": "info",
        "path": args.input,
        "size": len(data),
        "sha256": _sha256(data),
        "format": p.format_name,
        "machine": p.machine_name,
        "sections": p.num_sections,
        "file_alignment": p.file_alignment,
        "signed": p.signed,
        "cert_table": (
            {"offset": p.cert_off, "size": p.cert_size} if p.signed else None
        ),
    }
    _emit(args, payload, lines)
    return 0


def _cmd_extract(args: argparse.Namespace) -> int:
    data = _read_file(args.input)
    if data[:2] != b"MZ":
        raise CertAlphaError(
            "BAD_PE",
            "extract expects a PE input (.exe/.dll)",
            "use 'inspect' for raw PKCS#7 (.p7b/.der) files",
        )
    blobs = ops.extract_certificate_blobs(data)
    prefix = args.prefix or os.path.splitext(os.path.basename(args.input))[0]
    written: List[Dict[str, Any]] = []
    for index, blob in enumerate(blobs, 1):
        path = os.path.join(args.out_dir, "%s.cert%d.p7b" % (prefix, index))
        _write_file(path, blob)
        written.append(
            {"path": path, "size": len(blob), "sha256": _sha256(blob)}
        )

    lines = ["extracted %d certificate blob(s) from %s" % (len(written), args.input)]
    for item in written:
        lines.append(
            "  -> %s  (%d bytes, sha256=%s)"
            % (item["path"], item["size"], item["sha256"])
        )
    payload = {
        "status": "OK",
        "command": "extract",
        "input": args.input,
        "extracted": written,
    }
    _emit(args, payload, lines)
    return 0


def _collect_cert_blobs(data: bytes):
    """Return (list of PKCS#7 blobs, origin description)."""
    if data[:2] == b"MZ":
        p = pemod.parse_pe(data)
        if not p.signed:
            raise CertAlphaError(
                "NO_SIGNATURE",
                "input PE is unsigned (no certificate table)",
                "supply a signed PE or a raw .p7b file",
            )
        entries = ops.parse_certificate_table(
            data[p.cert_off : p.cert_off + p.cert_size]
        )
        return [e[8:] for e in entries], "PE certificate table"
    return [data], "raw PKCS#7 file"


def _cmd_inspect(args: argparse.Namespace) -> int:
    data = _read_file(args.input)
    blobs, origin = _collect_cert_blobs(data)

    reports: List[Dict[str, Any]] = []
    signer_der_raw: Optional[bytes] = None
    signer_serial: Optional[bytes] = None

    parsed: List[Any] = []
    for index, blob in enumerate(blobs, 1):
        signed_data = pki.parse_signed_data(blob)
        certs, signers, _content_info = pki.split_signed_data(signed_data)
        serial = pki.signer_serial(signers)
        if serial is not None and signer_serial is None:
            signer_serial = serial
        signer = pki.find_signer_cert(certs, serial)
        if signer is not None and signer_der_raw is None:
            signer_der_raw = signer.raw
        parsed.append((index, certs))

    for index, certs in parsed:
        for cert in certs:
            try:
                info = pki.cert_info(cert)
            except Exception as exc:  # noqa: BLE001 - report, don't abort the bag
                reports.append(
                    {
                        "entry": index,
                        "role": "unknown",
                        "error": "unparsable certificate: %s" % exc,
                    }
                )
                continue
            role = "signer" if cert.raw == signer_der_raw else "chain"
            info["entry"] = index
            info["role"] = role
            reports.append(info)

    lines = [
        "input      : %s (%s, %d signature blob(s))"
        % (args.input, origin, len(blobs))
    ]
    for info in reports:
        if "error" in info:
            lines.append(
                "[%d] unparsable: %s" % (info["entry"], info["error"])
            )
            continue
        lines.append(
            "[%d] role=%s  %s" % (info["entry"], info["role"], info["subject"] or "(no subject)")
        )
        lines.append("    issuer      : %s" % info["issuer"])
        lines.append("    serial      : %s" % info["serial"])
        lines.append("    validity    : %s" % _validity_label(info))
        lines.append(
            "    key         : %s%s"
            % (
                info["key_algorithm"],
                ""
                if info["key_size_bits"] is None
                else " (%d bits)" % info["key_size_bits"],
            )
        )
        lines.append("    sig alg     : %s" % info["signature_algorithm"])
        lines.append("    sha256      : %s" % info["sha256"])
        lines.append("    sha1        : %s" % info["sha1"])

    payload = {
        "status": "OK",
        "command": "inspect",
        "input": args.input,
        "origin": origin,
        "signature_blobs": len(blobs),
        "certificates": reports,
    }
    _emit(args, payload, lines)
    return 0


def _verify_lines(st: Dict[str, Any]) -> List[str]:
    if not st.get("signed"):
        return ["signed     : no", st.get("conclusion", "")]
    lines = [
        "signed     : yes (table @0x%X, %d bytes, %d cert blob(s))"
        % (st.get("cert_table_offset") or 0, st.get("cert_table_size") or 0,
           st.get("certificate_count") or 0),
        "parseable  : %s" % ("yes" if st.get("parseable") else "no"),
    ]
    signer = st.get("signer")
    if isinstance(signer, dict):
        lines.append("signer     : %s" % signer.get("subject"))
        lines.append("issuer     : %s" % signer.get("issuer"))
        lines.append(
            "validity   : %s (%s .. %s)"
            % (
                st.get("validity_window") or "unknown",
                signer.get("not_before"),
                signer.get("not_after"),
            )
        )
        lines.append("key        : %s" % signer.get("key_algorithm"))
    if st.get("hash_algorithm"):
        lines.append("hash alg   : %s" % st.get("hash_algorithm"))
        lines.append("expected   : %s" % st.get("expected_digest"))
        lines.append("computed   : %s" % st.get("computed_digest"))
        match = st.get("digest_match")
        lines.append(
            "digest     : %s"
            % ("MATCH" if match is True else ("MISMATCH" if match is False else "n/a"))
        )
    if st.get("page_hashes_present"):
        lines.append("page hashes: embedded")
    lines.append("conclusion : %s" % st.get("conclusion"))
    return lines


def _cmd_verify(args: argparse.Namespace) -> int:
    data = _read_file(args.input)
    st = ops.verify_signature(data)
    payload = {"status": "OK", "command": "verify", "input": args.input, "verify": st}
    _emit(args, payload, _verify_lines(st))
    return 0


def _cmd_strip(args: argparse.Namespace) -> int:
    data = _read_file(args.input)
    _guard_distinct_paths(args.input, args.output, args.force)
    out = ops.strip_signature(data, update_checksum=args.update_checksum)
    _write_file(args.output, out)
    lines = [
        "stripped signature from %s" % args.input,
        "  input  : %d bytes (signed)" % len(data),
        "  output : %d bytes (unsigned) -> %s" % (len(out), args.output),
        "  sha256 : %s" % _sha256(out),
    ]
    payload = {
        "status": "OK",
        "command": "strip",
        "input": args.input,
        "output": args.output,
        "output_size": len(out),
        "output_sha256": _sha256(out),
    }
    _emit(args, payload, lines)
    return 0


def _cmd_inject(args: argparse.Namespace) -> int:
    # [Xyberix] — Cert Transplant Module — Requires Manual Execution
    if not args.ack_authorized:
        raise CertAlphaError(
            "ACK_REQUIRED",
            ACK_TEXT,
            "re-run with --ack-authorized to confirm you are authorized to "
            "test these binaries",
        )
    src = _read_file(args.src)
    dst = _read_file(args.dst)
    _guard_distinct_paths(args.dst, args.output, args.force)

    out = ops.inject_certificate(
        src, dst, mode=args.mode, update_checksum=args.update_checksum
    )
    _write_file(args.output, out)

    st = ops.verify_signature(out)
    lines = [
        "transplanted certificate table: %s -> %s" % (args.src, args.dst),
        "  mode   : %s" % args.mode,
        "  output : %d bytes -> %s" % (len(out), args.output),
        "  sha256 : %s" % _sha256(out),
        "",
    ]
    lines.extend(_verify_lines(st))
    payload = {
        "status": "OK",
        "command": "inject",
        "mode": args.mode,
        "source": args.src,
        "target": args.dst,
        "output": args.output,
        "output_size": len(out),
        "output_sha256": _sha256(out),
        "verify": st,
    }
    _emit(args, payload, lines)
    return 0


# --- parser ----------------------------------------------------------------

def _common_flags() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="machine-readable JSON output",
    )
    common.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="raise unexpected exceptions instead of reporting them",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_flags()
    parser = argparse.ArgumentParser(
        prog="certalpha",
        description=(
            "CertAlpha — extract, inspect, strip and transplant Authenticode "
            "certificates between PE files. Offline; never executes the "
            "binaries it processes."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version="%s %s" % (__appname__, __version__)
    )
    parser.add_argument(
        "--json", action="store_true", help="machine-readable JSON output"
    )
    parser.add_argument(
        "--debug", action="store_true", help="raise unexpected exceptions"
    )

    sub = parser.add_subparsers(dest="command")

    p_info = sub.add_parser(
        "info", parents=[common], help="show PE structure + signature presence"
    )
    p_info.add_argument("input", help="PE file (.exe/.dll)")

    p_extract = sub.add_parser(
        "extract", parents=[common], help="extract certificate blob(s) from a signed PE"
    )
    p_extract.add_argument("input", help="signed donor PE (.exe/.dll)")
    p_extract.add_argument(
        "-o", "--out-dir", default=".", help="output directory (default: .)"
    )
    p_extract.add_argument("--prefix", default=None, help="output filename prefix")

    p_inspect = sub.add_parser(
        "inspect", parents=[common], help="pretty-print certificate details"
    )
    p_inspect.add_argument("input", help="PE file or raw .p7b/.der")

    p_verify = sub.add_parser(
        "verify", parents=[common], help="offline Authenticode digest evaluation"
    )
    p_verify.add_argument("input", help="PE file (.exe/.dll)")

    p_strip = sub.add_parser(
        "strip", parents=[common], help="remove the certificate table from a PE"
    )
    p_strip.add_argument("input", help="signed PE (.exe/.dll)")
    p_strip.add_argument("-o", "--output", required=True, help="output PE path")
    p_strip.add_argument(
        "--update-checksum",
        action="store_true",
        help="recompute the (cosmetic) PE checksum after modification",
    )
    p_strip.add_argument(
        "--force", action="store_true", help="allow in-place modification (-o == input)"
    )

    p_inject = sub.add_parser(
        "inject",
        parents=[common],
        help="graft a donor certificate into a target PE (risk-gated)",
    )
    p_inject.add_argument("src", help="cert donor: signed PE, or raw .p7b/.der")
    p_inject.add_argument("dst", help="target PE to receive the certificate")
    p_inject.add_argument("-o", "--output", required=True, help="output PE path")
    p_inject.add_argument(
        "--mode",
        choices=("replace", "append"),
        default="replace",
        help="replace existing target signature (default) or append alongside it",
    )
    p_inject.add_argument(
        "--ack-authorized",
        action="store_true",
        help="confirm you are authorized to perform signature transplantation",
    )
    p_inject.add_argument(
        "--update-checksum",
        action="store_true",
        help="recompute the (cosmetic) PE checksum after modification",
    )
    p_inject.add_argument(
        "--force", action="store_true", help="allow in-place modification (-o == input)"
    )

    return parser


HANDLERS = {
    "info": _cmd_info,
    "extract": _cmd_extract,
    "inspect": _cmd_inspect,
    "verify": _cmd_verify,
    "strip": _cmd_strip,
    "inject": _cmd_inject,
}


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        pass

    if not args.command:
        parser.print_help()
        return 0

    try:
        return HANDLERS[args.command](args)
    except CertAlphaError as exc:
        if getattr(args, "json", False):
            print(exc.to_json())
        else:
            print(exc.render(), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:  # noqa: BLE001 - last-resort error contract
        if getattr(args, "debug", False):
            raise
        err = CertAlphaError(
            "INTERNAL_ERROR",
            "%s: %s" % (type(exc).__name__, exc),
            "re-run with --debug for a traceback",
        )
        if getattr(args, "json", False):
            print(err.to_json())
        else:
            print(err.render(), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
