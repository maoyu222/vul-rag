"""Versioned lexical fingerprints. No source text is rewritten for inference."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

NORMALIZATION_VERSION = "c_cpp_tokens_v1"
TOKEN_RE = re.compile(
    r'(?P<raw>(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\([\s\S]*?\)(?P=delimiter)")'
    r'|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<literal>(?:u8|u|U|L)?"(?:\\[\s\S]|[^"\\])*"|(?:u8|u|U|L)?\'(?:\\[\s\S]|[^\'\\])*\')'
    r'|(?P<identifier>[A-Za-z_]\w*)'
    r'|(?P<number>\d+(?:\.\d+)?(?:[eEpP][+-]?\d+)?[A-Za-z0-9_]*)'
    r'|(?P<operator><<=|>>=|->\*|\.\*|\.\.\.|::|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|##)'
    r'|(?P<other>[^\s])'
)


def tokens(code: str) -> list[str]:
    return [m.group() for m in TOKEN_RE.finditer(code.replace("\r\n", "\n")) if m.lastgroup != "comment"]


def code_hash(code: str) -> str:
    return hashlib.sha256(json.dumps(tokens(code), ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def text(value) -> str:
    if value is None:
        return ""
    value = str(value).strip()
    return "" if value.lower() in {"none", "null", "nan", "n/a"} else value


def cwes(value) -> list[str]:
    if isinstance(value, list):
        values = value
    elif value is None or isinstance(value, str):
        values = re.findall(r"CWE-\d+", text(value), re.I)
    else:
        raise ValueError("CWE field must be string/list/null")
    result = []
    for item in values:
        item = text(item).upper()
        if item in {"NVD-CWE-NOINFO", "NVD-CWE-OTHER", "CWE-OTHER", "CWE-NOINFO", "UNKNOWN"}:
            continue
        if item and not re.fullmatch(r"CWE-\d+", item):
            raise ValueError(f"invalid CWE identifier: {item}")
        if item and item not in result:
            result.append(item)
    return result


def project_key(value: str, aliases: dict | None = None) -> str:
    key = text(value).lower().rstrip("/")
    if "://" in key:
        key = urlsplit(key).path.strip("/")
    if key.endswith(".git"):
        key = key[:-4]
    return (aliases or {}).get(key, key)


def function_name(code: str) -> str:
    # A conservative identity hint for official adjacent pairs, not an AST.
    prefix = re.sub(r"/\*[\s\S]*?\*/|//[^\n]*", " ", code).split("{", 1)[0]
    matches = re.findall(r"(?<!\w)([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\(", prefix)
    matches = [x for x in matches if x not in {"if", "while", "for", "sizeof", "__attribute__", "__declspec"}]
    return matches[0] if matches else ""


def language(value: str, path: str = "", dataset_default: str = "") -> tuple[str, str]:
    value = text(value).lower()
    aliases = {"c": "C", "c++": "C++", "cpp": "C++", "cxx": "C++", "cc": "C++", "c/c++": "C/C++"}
    if value:
        if value not in aliases:
            raise ValueError(f"non-C/C++ or unsupported explicit language: {value}")
        return aliases[value], "explicit_source_field"
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if suffix in {"py", "java", "js", "ts", "go", "rs", "php", "cs", "rb", "swift", "kt"}:
        raise ValueError(f"non-C/C++ source extension: {suffix}")
    if suffix in {"c", "cpp", "cxx", "cc", "h", "hpp", "hh", "hxx"}:
        return ("C" if suffix == "c" else "C/C++" if suffix == "h" else "C++"), "file_extension"
    if dataset_default in {"C", "C++", "C/C++"}:
        return dataset_default, "explicit_adapter_dataset_scope"
    raise ValueError("language is not known; supply a verified adapter language mapping")
