"""CertAlpha — Authenticode certificate forge & transplant toolkit.

[Xyberix] — Build only. This package never executes the binaries it processes,
performs no network I/O, spawns no processes, and writes nothing unless the
operator invokes a CLI command explicitly.

Operations
----------
extract : pull the Authenticode certificate (PKCS#7 / .p7b) out of a signed PE
inspect : pretty-print X.509 details of a signature (PE or raw .p7b)
strip   : remove the certificate table from a PE
inject  : graft a donor certificate table into a target PE (risk-gated)
verify  : offline Authenticode digest evaluation (match / mismatch)

Honest limitation (read before use):
    A transplanted certificate is NOT a cryptographically valid signature.
    Authenticode hashes the file body; moving the cert to a different binary
    makes the stored digest mismatch. Only naive checks (cert presence,
    parsed signer string without verification) can be fooled. Producing a
    genuinely valid signature requires the signer's private key
    (e.g. `signtool sign /f your_cert.pfx`).
"""

__appname__ = "CertAlpha"
__version__ = "1.0.0"

__all__ = ["__appname__", "__version__"]
