"""What a rich representation holds that its rendered text does not show.

A rich copy past the scan cap is scanned only in part. Its visible text is also
the plain representation, which is scanned on its own, so what the unscanned
tail can still hide is what never renders: a link's address, another attribute,
a comment, a script, an RTF field. `hidden_parts` pulls that out small enough to
scan whole. Repeated values, which are most of a large Office copy's markup, are
kept once, and inline media, which is most of the rest, is left out.
"""

from __future__ import annotations

import html
import logging
import time

import regex

log = logging.getLogger(__name__)

# Base64 media in a data: URI. One attribute can hold megabytes of it, and no
# rule finds a secret inside an image.
_INLINE_MEDIA = regex.compile(
    r"data:(?:image|font|audio|video)/[\w.+-]++(?:;[\w.+-]++(?:=[\w.+-]*+)?+)*+,"
    r"[A-Za-z0-9+/=%\s]*+",
    regex.I,
)

# An attribute anywhere in the markup, not only inside a tag: text that merely
# looks like one costs a little scanning, while matching tags whole first took
# three times as long on a large copy.
_ATTR = regex.compile(
    r"""\s([^\s=/<>"']++)\s*+=\s*+(?:"([^"]*+)"|'([^']*+)'|([^\s>"']++))"""
)
# A comment, script or style that never closes runs to the end, as a browser
# reads it, which also keeps an unclosed one from being searched past once per
# tag after it.
_RAW = regex.compile(
    r"<!--(.*?)(?:-->|\Z)|<(script|style)\b[^>]*+>(.*?)(?:</\2\s*+>|\Z)",
    regex.S | regex.I,
)

# A field's instruction -- `HYPERLINK "https://..."` -- with the one level of
# grouping Word and Cocoa put inside it.
_RTF_FIELD = regex.compile(
    r"\\fldinst\b((?:[^{}\\]++|\\.|\{(?:[^{}\\]++|\\.)*+\})*+)", regex.S
)
_RTF_TOKEN = regex.compile(
    r"\\'([0-9a-fA-F]{2})|\\u(-?\d+) ?\??|\\([\\{}])|\\[a-zA-Z]+-?\d* ?|\\.|[{}\r\n]",
    regex.S,
)


def hidden_parts(name: str, value: str, *, timeout: float | None = None) -> str | None:
    """What the representation `name` holds beyond its rendered text, one part
    per line and each once; None when this cannot say, for a kind it does not
    read or markup it cannot read within `timeout` seconds.
    """
    kind = name.lower()
    deadline = None if timeout is None else time.monotonic() + timeout
    try:
        if "html" in kind:
            parts = _html_parts(value, deadline)
        elif "rtf" in kind:
            parts = _rtf_parts(value, deadline)
        else:
            return None
    except TimeoutError:
        log.warning("could not read the %s representation in time", name)
        return None
    stripped = (_INLINE_MEDIA.sub("", part).strip() for part in parts)
    return "\n".join(dict.fromkeys(part for part in stripped if part))


def _left(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("the markup's read budget is spent")
    return left


def _html_parts(value: str, deadline: float | None) -> list[str]:
    parts = [
        comment or body
        for comment, _tag, body in _RAW.findall(value, timeout=_left(deadline))
    ]
    # Deduplicated before unescaping, which is the slow part: a large table
    # repeats a handful of attributes per cell.
    attrs = dict.fromkeys(_ATTR.findall(value, timeout=_left(deadline)))
    # Kept with its name, the context a generic rule needs: `api_key="..."` is
    # a finding where the bare value is not.
    parts.extend(
        f'{name}="{html.unescape(double or single or bare)}"'
        for name, double, single, bare in attrs
    )
    return parts


def _rtf_parts(value: str, deadline: float | None) -> list[str]:
    return [
        _RTF_TOKEN.sub(_rtf_char, m.group(1))
        for m in _RTF_FIELD.finditer(value, timeout=_left(deadline))
    ]


def _rtf_char(m: regex.Match) -> str:
    hex_byte, code, escaped = m.group(1, 2, 3)
    if hex_byte is not None:
        return bytes([int(hex_byte, 16)]).decode("cp1252", "replace")
    if code is not None:
        return chr(int(code) % 0x10000)
    return escaped or ""
