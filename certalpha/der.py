"""Minimal DER/ASN.1 reader for Authenticode / X.509 work (stdlib only).

Static byte parsing — no execution, no network, no writes.
Supports the definite-length DER subset used by certificates and PKCS#7.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, List, Optional, Tuple

# Tag classes
UNIVERSAL = 0x00
APPLICATION = 0x40
CONTEXT = 0x80
PRIVATE = 0xC0

# Universal tags
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_ENUMERATED = 0x0A
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_PRINTABLE_STRING = 0x13
TAG_T61_STRING = 0x14
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_BMP_STRING = 0x1E


class DerError(ValueError):
    """Raised when content cannot be decoded as DER."""


@dataclass(frozen=True)
class DerNode:
    """One parsed ASN.1 element. Offsets are absolute within ``buf``."""

    buf: bytes
    cls: int
    constructed: bool
    tag: int
    start: int          # offset of the first tag byte
    content_start: int  # offset of first content byte
    end: int            # offset one past the element

    @property
    def content(self) -> bytes:
        return self.buf[self.content_start : self.end]

    @property
    def raw(self) -> bytes:
        return self.buf[self.start : self.end]

    @property
    def is_universal(self) -> bool:
        return self.cls == UNIVERSAL

    @property
    def is_context(self) -> bool:
        return self.cls == CONTEXT

    def children(self) -> Iterator["DerNode"]:
        if not self.constructed:
            return
        pos = self.content_start
        while pos < self.end:
            node, nxt = parse_der(self.buf, pos)
            if nxt <= pos:
                raise DerError("zero-length ASN.1 element inside container")
            yield node
            pos = nxt

    def child_list(self) -> List["DerNode"]:
        return list(self.children())

    def first(self, cls: int, tag: int) -> Optional["DerNode"]:
        for child in self.children():
            if child.cls == cls and child.tag == tag:
                return child
        return None


def parse_der(buf: bytes, pos: int = 0) -> Tuple[DerNode, int]:
    """Parse one TLV starting at ``pos``; return (node, offset_past_node)."""
    start = pos
    if pos >= len(buf):
        raise DerError("unexpected end of data while reading tag")
    first = buf[pos]
    pos += 1
    cls = first & 0xC0
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:  # long-form tag number
        tag = 0
        while True:
            if pos >= len(buf):
                raise DerError("truncated long-form tag")
            b = buf[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        if tag > 0xFFFFFF:
            raise DerError("implausible ASN.1 tag number")

    if pos >= len(buf):
        raise DerError("truncated ASN.1 length")
    lb = buf[pos]
    pos += 1
    if lb == 0x80:
        raise DerError("indefinite-length encoding is not valid DER")
    if lb & 0x80:
        n = lb & 0x7F
        if n == 0 or n > 4:
            raise DerError("unsupported ASN.1 length encoding")
        if pos + n > len(buf):
            raise DerError("truncated ASN.1 length")
        length = int.from_bytes(buf[pos : pos + n], "big")
        pos += n
    else:
        length = lb

    content_start = pos
    end = content_start + length
    if end > len(buf):
        raise DerError(
            "ASN.1 element overruns buffer (needs %d, have %d)" % (end, len(buf))
        )
    return (
        DerNode(
            buf=buf,
            cls=cls,
            constructed=constructed,
            tag=tag,
            start=start,
            content_start=content_start,
            end=end,
        ),
        end,
    )


def decode_oid(node: DerNode) -> str:
    """Decode an OBJECT IDENTIFIER to dotted-decimal form."""
    if not (node.is_universal and node.tag == TAG_OID):
        raise DerError("expected OBJECT IDENTIFIER, got tag 0x%02X" % node.tag)
    data = node.content
    if not data:
        raise DerError("empty OBJECT IDENTIFIER")
    first = data[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    value = 0
    pending = False
    for b in data[1:]:
        value = (value << 7) | (b & 0x7F)
        pending = bool(b & 0x80)
        if not pending:
            arcs.append(value)
            value = 0
    if pending:
        raise DerError("truncated OBJECT IDENTIFIER arc")
    return ".".join(str(a) for a in arcs)


def decode_integer(node: DerNode) -> int:
    """Decode INTEGER as signed two's-complement."""
    if not (node.is_universal and node.tag == TAG_INTEGER):
        raise DerError("expected INTEGER")
    if not node.content:
        raise DerError("empty INTEGER")
    return int.from_bytes(node.content, "big", signed=True)


def decode_bitstring(node: DerNode) -> bytes:
    """Decode BIT STRING payload (usage-count byte stripped)."""
    if not (node.is_universal and node.tag == TAG_BIT_STRING):
        raise DerError("expected BIT STRING")
    data = node.content
    if not data:
        raise DerError("empty BIT STRING")
    return data[1:]


def decode_string(node: DerNode) -> str:
    """Decode the common ASN.1 string types to ``str``."""
    data = node.content
    if node.tag == TAG_UTF8_STRING:
        return data.decode("utf-8", "replace")
    if node.tag == TAG_BMP_STRING:
        return data.decode("utf-16-be", "replace")
    if node.tag in (TAG_PRINTABLE_STRING, TAG_IA5_STRING, TAG_T61_STRING):
        return data.decode("latin-1", "replace")
    return data.decode("utf-8", "replace")


def decode_time(node: DerNode) -> Optional[datetime]:
    """Decode UTCTime / GeneralizedTime to an aware UTC datetime (best effort)."""
    if node.tag not in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
        raise DerError("expected time value")
    raw = node.content.decode("ascii", "replace").strip()
    digits = "".join(ch for ch in raw if ch.isdigit())
    try:
        if node.tag == TAG_UTC_TIME:
            if len(digits) >= 12:
                return datetime.strptime(digits[:12], "%y%m%d%H%M%S").replace(
                    tzinfo=timezone.utc
                )
            if len(digits) >= 10:
                return datetime.strptime(digits[:10], "%y%m%d%H%M").replace(
                    tzinfo=timezone.utc
                )
            return None
        if len(digits) >= 14:
            return datetime.strptime(digits[:14], "%Y%m%d%H%M%S").replace(
                tzinfo=timezone.utc
            )
        return None
    except ValueError:
        return None
