# CertAlpha — usage

Authenticode certificate **forge & transplant** toolkit for PE files.
Extract the embedded certificate from any signed `.exe`/`.dll`, inspect it,
and graft it into another application of your choice.

- **Stack:** Python ≥ 3.8, standard library only (no third-party packages)
- **Targets:** Windows / Linux / macOS (pure byte-level PE manipulation)
- **I/O model:** reads only the paths you name, writes only the `-o` path you name
- **Guarantees:** no process execution, no network access, no persistence,
  no auto-run — the tool does nothing until you invoke a command

---

## ⚠️ RISK ALERT (read before use)

```markdown
[⚠️ RISK ALERT]

This tool transplants Authenticode certificates between PE binaries — a
signature-spoofing technique. It runs entirely offline and writes only the
output file you specify.

Do you want to use it?
✅ YES — only on binaries/systems you are authorized to test. (The tool
   enforces this with --ack-authorized on the `inject` command.)
❌ NO  — do not run the `inject` command.
```

**Cryptographic reality (do not skip):**

A transplanted certificate is **NOT a valid signature**. Authenticode signs a
hash of the file body; moving that certificate to a different binary makes the
stored digest mismatch. What you get:

| Check type | Result after transplant |
|---|---|
| "Is a certificate table present?" (naive) | fooled |
| "Who is the parsed signer?" (no chain/hash verify) | fooled |
| `signtool verify /pa`, SmartScreen, catalog/chain validation | **rejects** |
| Driver/kernel loading (.sys) | **rejects** |

Producing a *genuinely* valid signature requires the signer's **private key**,
e.g. `signtool sign /f your_cert.pfx /fd sha256 {{OUTPUT_PE}}` — that is
signing, not forging, and only your own certificate should be used for it.

Legitimate uses: validating that your allowlist/EDR actually *verifies*
signatures instead of merely *seeing* them, red-team lab fixtures, malware
analysis pipelines, reverse-engineering study.

---

## Commands

| Command | Purpose |
|---|---|
| `info` | PE structure + signature presence |
| `extract` | pull certificate blob(s) (`.p7b`) out of a signed PE |
| `inspect` | pretty-print X.509 details (subject/issuer/serial/validity/keys/fingerprints) |
| `verify` | offline Authenticode digest evaluation (match / mismatch) |
| `strip` | remove the certificate table |
| `inject` | graft a donor certificate into a target PE — **risk-gated** |

All commands accept `--json` for machine-readable output.
Exit codes: `0` success · `2` operational error (structured) · `3` internal error.

## Examples

```bash
# 1. What am I looking at?
python -m certalpha info {{TARGET_PE}}

# 2. Forge: pull the certificate out of the donor
python -m certalpha extract {{DONOR_PE}} -o ./extracted
#    -> ./extracted/{{DONOR_STEM}}.cert1.p7b

# 3. Who does that certificate claim to be?
python -m certalpha inspect {{DONOR_PE}}

# 4. Inject: graft the donor cert into your chosen application
python -m certalpha inject {{DONOR_PE}} {{TARGET_PE}} -o {{OUTPUT_PE}} --ack-authorized

# 5. Honest post-check (also printed automatically after inject)
python -m certalpha verify {{OUTPUT_PE}}

# 6. Remove a signature
python -m certalpha strip {{TARGET_PE}} -o {{TARGET_PE}}.unsigned.exe
```

### `inject` reference

```
certalpha inject SRC DST -o OUTPUT [--mode replace|append]
                    [--ack-authorized] [--update-checksum] [--force] [--json]
```

- `SRC` — cert donor: a signed PE **or** a raw `.p7b`/`.der` blob
  (e.g. one produced by `extract`)
- `DST` — target PE to receive the certificate
- `--mode replace` (default) — drop the target's existing signature first
- `--mode append` — keep the target's signature and add the donor's as a
  second `WIN_CERTIFICATE` entry (target must be EOF-signed)
- `--ack-authorized` — required; confirms authorized use (risk gate)
- `--update-checksum` — recompute the cosmetic PE checksum (excluded from the
  Authenticode hash; drivers are the main case where it matters)
- `--force` — allow `-o` to equal the input (in-place edit)

## Error contract

Errors are structured (Xyberix format):

```json
{
  "status": "ERROR",
  "code": "NO_SIGNATURE",
  "message": "donor PE has no certificate table to copy",
  "suggestion": "use a signed donor PE, or pass a raw .p7b/.der as the source"
}
```

Common codes: `FILE_NOT_FOUND`, `BAD_PE`, `NO_SIGNATURE`, `BAD_CERT_TABLE`,
`PKCS7_PARSE`, `NO_CERT_DIR`, `UNSUPPORTED_LAYOUT`, `ACK_REQUIRED`,
`SAME_PATH`, `IO_ERROR`, `UNSUPPORTED_ALG`, `INTERNAL_ERROR`.

## Self-test

```bash
python tests/selftest.py
```

Builds synthetic PE/X.509/PKCS#7 fixtures in memory, exercises every code
path (extract → inject → verify → strip round-trip, append/replace modes,
PE32/PE32+, error contract, CLI smoke in a temp dir), prints PASS/FAIL per
check, exits `0`/`1`. **Fully offline; executes no PE.**

> **Note:** the self-test proves internal self-consistency (digest computed
> and embedded by the same code). To validate against a reference
> implementation, run `certalpha verify {{SIGNED_PE}}` on a real signed
> binary and confirm it reports `digest MATCH`, then cross-check with
> `signtool verify /pa {{SIGNED_PE}}`.

## Implementation notes

- Certificate table = `IMAGE_DIRECTORY_ENTRY_SECURITY` data directory
  (offset is a **file offset**, not an RVA) holding `WIN_CERTIFICATE`
  entries (`wRevision=0x0200`, `wCertificateType=0x02` = PKCS SignedData),
  each padded to 8 bytes; injection always aligns the table to 8 bytes.
- Authenticode hash excludes: the `CheckSum` field, the Security
  data-directory entry, and the certificate table itself (spec-confirmed).
- `verify` evaluates digest + signer identity + validity window only;
  it deliberately performs **no** trust-chain evaluation (no trust store,
  no network, no revocation checks).

## Manifest (config.meta)

See `config.meta` for the machine-readable manifest: dependencies, target
OS, runtime requirements, risk level, and file inventory.
