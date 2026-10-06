# CertAlpha

[![All rights reserved](https://img.shields.io/badge/license-all%20rights%20reserved-red.svg)](#copyright)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Stdlib only](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](requirements.txt)

**Forge & transplant Authenticode certificates between Windows PE binaries (`.exe` / `.dll`).**

Extract the embedded certificate from any signed donor, inspect its X.509 identity,
graft it into a target application of your choice, evaluate the result offline, or
strip signatures entirely.

- **Python ≥ 3.8, standard library only** — no third-party packages to install
- **Offline by design** — no network, no subprocess, no persistence, no auto-execution;
  reads/writes only the paths you explicitly name
- **Risk-gated** — the `inject` command refuses to run without `--ack-authorized`
- **Honest** — `verify` computes the real Authenticode digest and tells you when a
  transplanted signature is cryptographically invalid (it always is — see below)

## Commands

| Command | Purpose |
|---|---|
| `info` | PE structure + signature presence |
| `extract` | pull certificate blob(s) (`.p7b`) out of a signed PE |
| `inspect` | pretty-print X.509 details (subject/issuer/serial/validity/keys/fingerprints) |
| `verify` | offline Authenticode digest evaluation (match / mismatch) |
| `strip` | remove the certificate table |
| `inject` | graft a donor certificate into a target PE — **risk-gated** |

Every command accepts `--json` for machine-readable output.
Exit codes: `0` success · `2` operational error (structured) · `3` internal error.

## Quick start

Run from the repository root (no installation step needed):

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

`inject` details:

```
certalpha inject SRC DST -o OUTPUT [--mode replace|append]
                    [--ack-authorized] [--update-checksum] [--force] [--json]
```

- `SRC` — cert donor: a signed PE **or** a raw `.p7b`/`.der` blob (e.g. from `extract`)
- `DST` — target PE to receive the certificate
- `--mode replace` (default) — drop the target's existing signature first
- `--mode append` — keep the target's signature, add the donor's as a second entry
- `--ack-authorized` — **required**; confirms authorized use (risk gate)
- `--force` — allow `-o` to equal the input (in-place edit)

## ⚠️ What a transplanted certificate is (and isn't)

A transplanted certificate is **not a valid signature**. Authenticode signs a hash of
the file body — moving that certificate to a different binary makes the stored digest
mismatch. What you actually get:

| Check type | Result after transplant |
|---|---|
| "Is a certificate table present?" (naive) | fooled |
| "Who is the parsed signer?" (no chain/hash verify) | fooled |
| `signtool verify /pa`, SmartScreen, chain validation | **rejects** |
| Driver/kernel loading (`.sys`) | **rejects** |

Producing a *genuinely* valid signature requires the signer's **private key**, e.g.
`signtool sign /f your_cert.pfx /fd sha256 {{OUTPUT_PE}}` — that is signing, not
forging, and only your own certificate should be used for it.

**Authorized testing only.** Intended for validating that your allowlist/EDR actually
*verifies* signatures instead of merely *seeing* them, red-team lab fixtures, malware
analysis pipelines, and reverse-engineering study. The full risk notice lives in
[`usage.md`](usage.md).

## Self-test

```bash
python tests/selftest.py
```

Builds synthetic PE/X.509/PKCS#7 fixtures in memory and exercises every code path:
extract → inject (`replace`/`append`) → verify → strip round-trip, PE32/PE32+, the
JSON error contract, and a CLI smoke test in a temp directory. Prints PASS/FAIL per
check; exits `0` on success, `1` on failure. **Fully offline; executes no PE.**

## Project layout

```
certalpha/            # package (pe.py, der.py, pki.py, ops.py, cli.py, errors.py)
tests/selftest.py     # offline self-test (~80 checks)
usage.md              # full command reference, risk notice, error contract
config.meta           # machine-readable manifest (dependencies, OS, risk level)
requirements.txt      # dependency declaration (stdlib only)
```

Errors are structured everywhere:

```json
{
  "status": "ERROR",
  "code": "NO_SIGNATURE",
  "message": "donor PE has no certificate table to copy",
  "suggestion": "use a signed donor PE, or pass a raw .p7b/.der as the source"
}
```

## Copyright

© 2026 WDRXN. **All rights reserved.**

No license is granted. This software may not be used, copied, modified,
distributed, or incorporated into other work — in whole or in part — without
explicit written permission from the author.
