"""PII detection with checksum validation (Luhn for cards, Verhoeff for Aadhaar)."""
import re
from typing import Iterable, List

from .core import Finding, Guard

# ---- Verhoeff (used by India's Aadhaar numbers) -------------------------------
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_digits = lambda s: re.sub(r"\D", "", s)

_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE_IN = re.compile(r"(?<![\d+])(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_PHONE_INTL = re.compile(r"(?<![\w+])\+(?!91)[1-9]\d{0,2}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")

_SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
_PIN = re.compile(r"(?i)\b(?:pin(?:\s?code)?|postal code|zip)\b\W{0,3}([1-9]\d{5})(?!\d)")
# cue-based heuristics (opt-in; noisy by nature)
_TITLE = r"(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt|Sri|Mx)\.?"
_NAME = re.compile(rf"\b{_TITLE}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){{0,2}}")
_NAME_CUE = re.compile(r"(?i:\b(?:my name is|i am called|name:|this is))\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})")
_ADDRESS = re.compile(
    r"(?i)\b(?:flat|house|plot|door)\s*(?:no\.?|number|#)?\s*[\w/-]+,?\s+[\w .,'/-]{3,60}?"
    r"\b(?:road|rd|street|st|lane|nagar|colony|sector|marg|avenue|ave|block|society|apartments?)\b[\w ,.-]{0,40}")

ALL_TYPES = ("email", "phone", "card", "aadhaar", "pan", "ipv4", "ssn", "pincode")
OPT_IN_TYPES = ("name", "address")      # heuristic, off by default


class PIIGuard(Guard):
    name = "pii"

    def __init__(self, types: Iterable[str] = ALL_TYPES):
        self.types = tuple(types)
        unknown = set(self.types) - set(ALL_TYPES) - set(OPT_IN_TYPES)
        if unknown:
            raise ValueError(f"unknown PII types: {sorted(unknown)}")

    def scan(self, text: str) -> List[Finding]:
        out: List[Finding] = []
        add = lambda rule, m: out.append(Finding("pii", rule, m.start(), m.end(), m.group()))
        if "email" in self.types:
            for m in _EMAIL.finditer(text):
                add("email", m)
        if "aadhaar" in self.types:
            for m in _AADHAAR.finditer(text):
                d = _digits(m.group())
                if len(d) == 12 and verhoeff_valid(d):
                    add("aadhaar", m)
        if "card" in self.types:
            for m in _CARD.finditer(text):
                d = _digits(m.group())
                if 13 <= len(d) <= 19 and luhn_valid(d) and len(set(d)) > 1:
                    add("card", m)
        if "pan" in self.types:
            for m in _PAN.finditer(text):
                add("pan", m)
        if "phone" in self.types:
            for rx in (_PHONE_IN, _PHONE_INTL):
                for m in rx.finditer(text):
                    add("phone", m)
        if "ipv4" in self.types:
            for m in _IPV4.finditer(text):
                add("ipv4", m)
        if "ssn" in self.types:
            for m in _SSN.finditer(text):
                add("ssn", m)
        if "pincode" in self.types:
            for m in _PIN.finditer(text):
                out.append(Finding("pii", "pincode", m.start(1), m.end(1), m.group(1)))
        if "name" in self.types:
            for m in _NAME.finditer(text):
                add("name", m)
            for m in _NAME_CUE.finditer(text):
                out.append(Finding("pii", "name", m.start(1), m.end(1), m.group(1)))
        if "address" in self.types:
            for m in _ADDRESS.finditer(text):
                add("address", m)
        return out
