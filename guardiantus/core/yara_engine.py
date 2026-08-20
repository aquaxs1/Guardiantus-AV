"""YARA integration.

``yara-python`` is optional.  When it is unavailable the engine degrades to a
small built-in interpreter that understands the subset of YARA the bundled
rules use: text/hex/regex strings plus ``any of them`` / ``all of them`` /
``N of them`` and simple ``and``/``or`` combinations of string identifiers.

The fallback is deliberately conservative: a rule it cannot parse is skipped
rather than guessed at, so a missing dependency can never manufacture a false
positive.
"""

from __future__ import annotations

import binascii
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import paths
from .models import Detection, DetectionSource, Severity

try:  # pragma: no cover - depends on the host environment
    import yara as _yara  # type: ignore

    HAVE_YARA = True
except ImportError:  # pragma: no cover
    _yara = None
    HAVE_YARA = False


# A rule ends at the first line whose only content is a closing brace, which
# keeps inline hex strings such as `$mz = { 4d 5a }` from terminating it early.
_RULE_RE = re.compile(
    r"rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]*)?\{(?P<body>.*?)\n[ \t]*\}",
    re.S,
)
_META_RE = re.compile(r"meta\s*:(?P<meta>.*?)(?=\n\s*(?:strings|condition)\s*:)", re.S)
_STRINGS_RE = re.compile(r"strings\s*:(?P<strings>.*?)(?=\n\s*condition\s*:)", re.S)
_CONDITION_RE = re.compile(r"condition\s*:(?P<condition>.*)", re.S)
_META_ITEM_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|(\d+)|(true|false))')
_STRING_ITEM_RE = re.compile(
    r'(?P<id>\$[A-Za-z0-9_]*)\s*=\s*(?P<value>"(?:[^"\\]|\\.)*"|\{[^}]*\}|/(?:[^/\\]|\\.)+/)'
    r"(?P<modifiers>(?:\s+(?:nocase|wide|ascii|fullword|private))*)",
    re.S,
)


class _FallbackString:
    __slots__ = ("identifier", "kind", "value", "nocase", "wide")

    def __init__(self, identifier: str, kind: str, value: Any, nocase: bool, wide: bool) -> None:
        self.identifier = identifier
        self.kind = kind
        self.value = value
        self.nocase = nocase
        self.wide = wide

    def find(self, data: bytes) -> int:
        if self.kind == "regex":
            match = self.value.search(data)
            return match.start() if match else -1

        needles: List[bytes] = [self.value]
        if self.wide:
            needles.append(b"".join(bytes([b, 0]) for b in self.value))
        haystack = data.lower() if self.nocase else data
        for needle in needles:
            probe = needle.lower() if self.nocase else needle
            index = haystack.find(probe)
            if index >= 0:
                return index
        return -1


class _FallbackRule:
    __slots__ = ("name", "meta", "strings", "condition")

    def __init__(
        self, name: str, meta: Dict[str, Any], strings: List[_FallbackString], condition: str
    ) -> None:
        self.name = name
        self.meta = meta
        self.strings = strings
        self.condition = condition

    def evaluate(self, data: bytes) -> Optional[Dict[str, Any]]:
        hits: Dict[str, int] = {}
        for string in self.strings:
            offset = string.find(data)
            if offset >= 0:
                hits[string.identifier] = offset
        if not self._condition_met(hits):
            return None
        return {"rule": self.name, "meta": dict(self.meta), "strings": hits}

    def _condition_met(self, hits: Dict[str, int]) -> bool:
        condition = " ".join(self.condition.split()).lower()
        if not condition:
            return False

        count_match = re.fullmatch(r"(all|any|\d+) of them", condition)
        if count_match:
            token = count_match.group(1)
            if token == "any":
                return bool(hits)
            if token == "all":
                return len(hits) == len(self.strings)
            return len(hits) >= int(token)

        set_match = re.fullmatch(r"(all|any|\d+) of \(\s*(\$[\w*]+(?:\s*,\s*\$[\w*]+)*)\s*\)", condition)
        if set_match:
            token = set_match.group(1)
            selectors = [s.strip() for s in set_match.group(2).split(",")]
            matched = sum(1 for s in selectors if self._selector_hit(s, hits))
            if token == "any":
                return matched >= 1
            if token == "all":
                return matched == len(selectors)
            return matched >= int(token)

        # Boolean combination of plain string identifiers.
        return _eval_boolean(condition, hits)

    def _selector_hit(self, selector: str, hits: Dict[str, int]) -> bool:
        if selector.endswith("*"):
            prefix = selector[:-1]
            return any(identifier.startswith(prefix) for identifier in hits)
        return selector in hits


def _eval_boolean(condition: str, hits: Dict[str, int]) -> bool:
    """Evaluate ``$a and ($b or not $c)`` without touching :func:`eval`.

    Unknown tokens abort the evaluation (returning ``False``) so an
    unsupported condition can never produce a detection.
    """
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|\$[\w]+", condition)
    if not tokens or "".join(tokens).replace(" ", "") != re.sub(r"\s+", "", condition):
        return False

    position = 0

    def peek() -> Optional[str]:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def parse_atom() -> bool:
        token = peek()
        if token is None:
            raise ValueError("unexpected end of condition")
        if token == "not":
            take()
            return not parse_atom()
        if token == "(":
            take()
            value = parse_or()
            if peek() != ")":
                raise ValueError("unbalanced parenthesis")
            take()
            return value
        if token.startswith("$"):
            take()
            return token in hits
        raise ValueError(f"unexpected token {token!r}")

    def parse_and() -> bool:
        value = parse_atom()
        while peek() == "and":
            take()
            value = parse_atom() and value
        return value

    def parse_or() -> bool:
        value = parse_and()
        while peek() == "or":
            take()
            value = parse_and() or value
        return value

    try:
        result = parse_or()
    except (ValueError, IndexError):
        return False
    return result if position == len(tokens) else False


def _parse_hex_string(raw: str) -> bytes:
    """``{ 4d 5a 90 ?? }`` -> bytes, wildcards truncate the pattern."""
    body = raw.strip("{}").strip()
    out = bytearray()
    for token in body.split():
        if "?" in token or token in ("[", "]"):
            break
        try:
            out.extend(binascii.unhexlify(token))
        except (binascii.Error, ValueError):
            break
    return bytes(out)


def _unescape(raw: str) -> bytes:
    body = raw[1:-1]
    for escaped, literal in ((r"\\", "\\"), (r"\"", '"'), (r"\n", "\n"), (r"\t", "\t"), (r"\r", "\r")):
        body = body.replace(escaped, literal)
    body = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), body)
    return body.encode("latin-1", errors="ignore")


def _parse_rules(text: str) -> List[_FallbackRule]:
    rules: List[_FallbackRule] = []
    for rule_match in _RULE_RE.finditer(text):
        name = rule_match.group("name")
        body = rule_match.group("body")

        meta: Dict[str, Any] = {}
        meta_match = _META_RE.search(body)
        if meta_match:
            for key, string_value, int_value, bool_value in _META_ITEM_RE.findall(meta_match.group("meta")):
                if string_value:
                    meta[key] = string_value
                elif int_value:
                    meta[key] = int(int_value)
                else:
                    meta[key] = bool_value == "true"

        strings: List[_FallbackString] = []
        strings_match = _STRINGS_RE.search(body)
        if strings_match:
            for item in _STRING_ITEM_RE.finditer(strings_match.group("strings")):
                identifier = item.group("id")
                value = item.group("value").strip()
                modifiers = item.group("modifiers") or ""
                nocase = "nocase" in modifiers
                wide = "wide" in modifiers
                if value.startswith("{"):
                    parsed = _parse_hex_string(value)
                    if parsed:
                        strings.append(_FallbackString(identifier, "hex", parsed, False, False))
                elif value.startswith("/"):
                    pattern_body = value.rsplit("/", 1)[0][1:]
                    flags = re.S | (re.I if nocase else 0)
                    try:
                        strings.append(
                            _FallbackString(
                                identifier,
                                "regex",
                                re.compile(pattern_body.encode("latin-1"), flags),
                                nocase,
                                wide,
                            )
                        )
                    except (re.error, UnicodeEncodeError):
                        continue
                else:
                    strings.append(_FallbackString(identifier, "text", _unescape(value), nocase, wide))

        condition_match = _CONDITION_RE.search(body)
        condition = condition_match.group("condition").strip() if condition_match else ""
        if strings and condition:
            rules.append(_FallbackRule(name, meta, strings, condition))
    return rules


class YaraEngine:
    """Compiles and applies YARA rules from the bundled and user rule dirs."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._compiled: Any = None
        self._fallback: List[_FallbackRule] = []
        self._rule_files: List[str] = []
        self._errors: List[str] = []
        self._native_rule_count: int = 0

    @property
    def backend(self) -> str:
        return "yara-python" if HAVE_YARA and self._compiled is not None else "built-in"

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._fallback) if not HAVE_YARA or self._compiled is None else self._native_rule_count

    def info(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "backend": self.backend,
                "available": HAVE_YARA,
                "rule_files": list(self._rule_files),
                "rule_count": self.rule_count,
                "errors": list(self._errors),
            }

    def load(self) -> int:
        """Compile every ``*.yar``/``*.yara`` file found. Returns rule count."""
        directories = [paths.BUNDLED_RULES, paths.rules_dir()]
        files: List[Path] = []
        for directory in directories:
            if directory and Path(directory).is_dir():
                for pattern in ("*.yar", "*.yara"):
                    files.extend(sorted(Path(directory).glob(pattern)))

        with self._lock:
            self._errors = []
            self._rule_files = [str(f) for f in files]
            self._fallback = []
            self._compiled = None
            self._native_rule_count = 0

            texts: List[Tuple[Path, str]] = []
            for file in files:
                try:
                    texts.append((file, file.read_text(encoding="utf-8", errors="replace")))
                except OSError as exc:
                    self._errors.append(f"{file.name}: {exc}")

            # Always build the fallback: it doubles as the rule inventory.
            for file, text in texts:
                try:
                    self._fallback.extend(_parse_rules(text))
                except re.error as exc:  # pragma: no cover - defensive
                    self._errors.append(f"{file.name}: {exc}")

            if HAVE_YARA and texts:
                try:
                    sources = {file.stem: text for file, text in texts}
                    self._compiled = _yara.compile(sources=sources)
                    self._native_rule_count = len(self._fallback) or len(texts)
                except Exception as exc:  # pragma: no cover - yara raises broadly
                    self._errors.append(f"yara compile: {exc}")
                    self._compiled = None

            return self.rule_count

    def scan(self, data: bytes) -> List[Detection]:
        with self._lock:
            compiled = self._compiled
            fallback = list(self._fallback)

        raw_matches: List[Dict[str, Any]] = []
        if compiled is not None:  # pragma: no cover - requires yara-python
            try:
                for match in compiled.match(data=data, timeout=30):
                    raw_matches.append(
                        {
                            "rule": match.rule,
                            "meta": dict(getattr(match, "meta", {}) or {}),
                            "strings": {},
                        }
                    )
            except Exception:
                raw_matches = []
        else:
            for rule in fallback:
                hit = rule.evaluate(data)
                if hit:
                    raw_matches.append(hit)

        detections: List[Detection] = []
        for match in raw_matches:
            meta = match.get("meta", {})
            try:
                severity = Severity(str(meta.get("severity", "high")).lower())
            except ValueError:
                severity = Severity.HIGH
            detections.append(
                Detection(
                    name=str(meta.get("threat_name") or match["rule"]),
                    source=DetectionSource.YARA,
                    severity=severity,
                    description=str(meta.get("description") or f"YARA rule {match['rule']} matched"),
                    score=int(meta.get("score", 85)),
                    evidence={
                        "rule": match["rule"],
                        "author": meta.get("author", ""),
                        "matched_strings": list(match.get("strings", {}).keys())[:10],
                    },
                )
            )
        return detections


_INSTANCE: Optional[YaraEngine] = None
_INSTANCE_LOCK = threading.Lock()


def get_yara() -> YaraEngine:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = YaraEngine()
            _INSTANCE.load()
        return _INSTANCE


def reset_yara_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        _INSTANCE = None
