from __future__ import annotations


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def parse_optional_hex(text: str | None) -> int | None:
    if text is None:
        return None
    token = text.strip()
    if token == "" or token == "-":
        return None
    return parse_hex(token)


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def parse_int_default(text: str | None, default: int = 0) -> int:
    token = (text or "").strip()
    if not token:
        return default
    return parse_int(token)


def split_pointer_type(type_name: str) -> tuple[str, int]:
    t = type_name.strip().replace(" ", "")
    stars = 0
    while t.endswith("*"):
        stars += 1
        t = t[:-1]
    return t, stars


def normalize_base_type_name(name: str) -> str:
    t = name.strip()
    t = t.replace("const ", "").replace("volatile ", "")
    t = t.replace("struct ", "").replace("class ", "")
    return t.strip()
