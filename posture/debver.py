"""Pure-Python Debian version comparison (dpkg --compare-versions semantics).

Used by the Ubuntu security-tracker witness to compare an installed dpkg
package/kernel version against the tracker's fixed version. Real dpkg
versions like ``6.17.9-6.17.0+signed`` and tilde pre-releases like
``1.0~rc1`` do NOT compare correctly under PEP 440
(``packaging.version.Version``): they either raise ``InvalidVersion`` (then a
plain string ``>=`` lex fallback gives the WRONG answer — e.g. ``1.0~rc1``
lex-compares ``>= 1.0`` but dpkg says ``1.0~rc1 < 1.0``) or parse to a
different ordering. This implements the real dpkg algorithm (Debian Policy
§5.6.12): ``[epoch:]upstream[-revision]``, with the dpkg lexical order (``~``
before everything, letters before non-letters, digit runs compared
numerically).

The system ``apt_pkg``/``debian`` modules aren't reliably available, and
shelling out to ``dpkg`` per CVE is too slow. Validate any change against
``dpkg --compare-versions``.

Ported from Forebode (forebode/debver.py), which validated it against dpkg.
"""

from __future__ import annotations


def _order(c: str) -> int:
    """dpkg char order for the non-digit prefix comparison.

    A digit (or end-of-string) is 0 — the prefix loop ends when it reaches a
    digit on both sides, so a digit here only matters relative to a non-digit
    on the other side (digits sort before letters/punctuation).
    """
    if c == "" or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _split_epoch(v: str) -> tuple[int, str]:
    if ":" in v:
        i = v.index(":")
        try:
            return int(v[:i]) if v[:i] else 0, v[i + 1:]
        except ValueError:
            return 0, v[i + 1:]
    return 0, v


def _split_rev(v: str) -> tuple[str, str]:
    if "-" in v:
        i = v.rindex("-")
        return v[:i], v[i + 1:]
    return v, ""


def _cmp_str(a: str, b: str) -> int:
    """Compare two version sub-strings (upstream or revision) per dpkg."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        # Non-digit prefix: compare char by char until both reach a digit.
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _order(a[i]) if i < la else _order("")
            bc = _order(b[j]) if j < lb else _order("")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        # Digit run: skip leading zeros, then compare by length (numeric) then
        # lexicographically (equal length => equal numeric).
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        da = 0
        while i + da < la and a[i + da].isdigit():
            da += 1
        db = 0
        while j + db < lb and b[j + db].isdigit():
            db += 1
        if da != db:
            return -1 if da < db else 1
        for k in range(da):
            if a[i + k] != b[j + k]:
                return -1 if a[i + k] < b[j + k] else 1
        i += da
        j += db
    return 0


def compare(a: str, b: str) -> int:
    """Return -1/0/1 comparing Debian versions a and b (dpkg semantics)."""
    ea, ra = _split_epoch(a)
    eb, rb = _split_epoch(b)
    if ea != eb:
        return -1 if ea < eb else 1
    ua, va = _split_rev(ra)
    ub, vb = _split_rev(rb)
    c = _cmp_str(ua, ub)
    if c != 0:
        return c
    return _cmp_str(va, vb)


def lt(a: str, b: str) -> bool:
    """True if Debian version a is strictly less than b."""
    return compare(a, b) < 0


def ge(a: str, b: str) -> bool:
    """True if Debian version a is greater than or equal to b (installed >= fixed)."""
    return compare(a, b) >= 0