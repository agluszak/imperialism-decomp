from __future__ import annotations

import csv
import re
from pathlib import Path

from imperialism_re.core.typing_utils import parse_int


def _token_to_int(token: str) -> int:
    txt = (token or "").strip()
    if not txt:
        raise ValueError("empty token")
    if txt.startswith("'") and txt.endswith("'") and len(txt) == 6:
        body = txt[1:-1]
        return int.from_bytes(body.encode("ascii", errors="strict"), byteorder="little", signed=False)
    if txt.lower().startswith("0x"):
        return int(txt, 16)
    if re.fullmatch(r"\d+", txt):
        return int(txt, 10)
    if len(txt) == 4 and txt.isascii():
        return int.from_bytes(txt.encode("ascii", errors="strict"), byteorder="little", signed=False)
    return parse_int(txt)


def parse_optional_int_token(token: str | None) -> int | None:
    txt = (token or "").strip()
    if not txt:
        return None
    return _token_to_int(txt)


def load_candidate_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def parse_domains_filter(raw: str) -> set[str]:
    return {x.strip().lower() for x in (raw or "").split(",") if x.strip()}


def row_domain(row: dict[str, str]) -> str:
    return (row.get("domain") or "").strip()


def row_kind(row: dict[str, str]) -> str:
    return (row.get("kind") or "").strip().lower()


def row_enum_path(row: dict[str, str]) -> str:
    return (row.get("enum_path") or "").strip()


def row_evidence_strength(row: dict[str, str]) -> int:
    txt = (row.get("evidence_strength") or "").strip()
    if not txt:
        return 0
    try:
        return int(txt)
    except Exception:
        return 0


def row_cluster_key(row: dict[str, str]) -> str:
    return (row.get("cluster_key") or "").strip()


def row_function_addr(row: dict[str, str]) -> int | None:
    for key in ("function_addr", "address"):
        v = parse_optional_int_token(row.get(key))
        if v is not None:
            return v
    return None


def row_param_name(row: dict[str, str]) -> str:
    return (row.get("param_name_or_field") or row.get("param_name") or "").strip()


def row_immediate_value(row: dict[str, str]) -> int | None:
    for key in ("immediate_value", "immediate_hex", "value"):
        v = parse_optional_int_token(row.get(key))
        if v is not None:
            return v
    return None


def row_struct_field_target(row: dict[str, str]) -> tuple[str, int] | None:
    struct_path = (row.get("struct_path") or "").strip()
    off = parse_optional_int_token(row.get("offset_hex") or row.get("offset") or row.get("offset_dec"))
    if struct_path and off is not None:
        return struct_path, off

    packed = (row.get("param_name_or_field") or "").strip()
    if not packed:
        return None
    m = re.match(r"^(?P<path>/[^+]+)\+0x(?P<off>[0-9a-fA-F]+)$", packed)
    if not m:
        return None
    return m.group("path"), int(m.group("off"), 16)


def should_accept_candidate(
    max_evidence: int,
    cluster_count: int,
    min_evidence: int,
    cluster_threshold: int,
) -> bool:
    if max_evidence < min_evidence:
        return False
    if cluster_threshold <= 1:
        return True
    return cluster_count >= cluster_threshold


def aggregate_param_candidates(
    rows: list[dict[str, str]],
    *,
    domains_filter: set[str],
    min_evidence: int,
    cluster_threshold: int,
) -> list[dict[str, object]]:
    grouped: dict[tuple[int, str, str, str], dict[str, object]] = {}

    for row in rows:
        kind = row_kind(row)
        if kind and kind not in {"param", "param_compare", "handler_param"}:
            continue
        domain = row_domain(row)
        if domains_filter and domain.lower() not in domains_filter:
            continue
        faddr = row_function_addr(row)
        pname = row_param_name(row)
        epath = row_enum_path(row)
        if faddr is None or not pname or not epath:
            continue

        key = (faddr, pname.lower(), epath, domain)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "function_addr": faddr,
                "param_name": pname,
                "enum_path": epath,
                "domain": domain,
                "max_evidence": 0,
                "clusters": set(),
                "values": set(),
                "row_count": 0,
            }
            grouped[key] = entry

        ev = row_evidence_strength(row)
        if ev > int(entry["max_evidence"]):
            entry["max_evidence"] = ev
        cluster = row_cluster_key(row)
        if cluster:
            entry["clusters"].add(cluster)
        value = row_immediate_value(row)
        if value is not None:
            entry["values"].add(value)
        entry["row_count"] = int(entry["row_count"]) + 1

    out: list[dict[str, object]] = []
    for entry in grouped.values():
        clusters = entry["clusters"]
        cluster_count = len(clusters) if clusters else 1
        if not should_accept_candidate(
            int(entry["max_evidence"]),
            cluster_count,
            min_evidence,
            cluster_threshold,
        ):
            continue
        out.append(
            {
                "function_addr": int(entry["function_addr"]),
                "param_name": str(entry["param_name"]),
                "enum_path": str(entry["enum_path"]),
                "domain": str(entry["domain"]),
                "max_evidence": int(entry["max_evidence"]),
                "cluster_count": cluster_count,
                "value_count": len(entry["values"]),
                "row_count": int(entry["row_count"]),
            }
        )

    out.sort(key=lambda x: (x["function_addr"], x["param_name"], x["enum_path"]))
    return out


def aggregate_struct_field_candidates(
    rows: list[dict[str, str]],
    *,
    domains_filter: set[str],
    min_evidence: int,
    cluster_threshold: int,
) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int, str, str], dict[str, object]] = {}

    for row in rows:
        kind = row_kind(row)
        if kind and kind not in {"struct_field", "field", "struct"}:
            continue
        domain = row_domain(row)
        if domains_filter and domain.lower() not in domains_filter:
            continue
        tgt = row_struct_field_target(row)
        epath = row_enum_path(row)
        if tgt is None or not epath:
            continue

        struct_path, off = tgt
        key = (struct_path, off, epath, domain)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "struct_path": struct_path,
                "offset": off,
                "enum_path": epath,
                "domain": domain,
                "max_evidence": 0,
                "clusters": set(),
                "row_count": 0,
                "field_name": (row.get("field_name") or "").strip(),
            }
            grouped[key] = entry

        ev = row_evidence_strength(row)
        if ev > int(entry["max_evidence"]):
            entry["max_evidence"] = ev
        cluster = row_cluster_key(row)
        if cluster:
            entry["clusters"].add(cluster)
        if not entry["field_name"]:
            entry["field_name"] = (row.get("field_name") or "").strip()
        entry["row_count"] = int(entry["row_count"]) + 1

    out: list[dict[str, object]] = []
    for entry in grouped.values():
        clusters = entry["clusters"]
        cluster_count = len(clusters) if clusters else 1
        if not should_accept_candidate(
            int(entry["max_evidence"]),
            cluster_count,
            min_evidence,
            cluster_threshold,
        ):
            continue
        out.append(
            {
                "struct_path": str(entry["struct_path"]),
                "offset": int(entry["offset"]),
                "enum_path": str(entry["enum_path"]),
                "domain": str(entry["domain"]),
                "max_evidence": int(entry["max_evidence"]),
                "cluster_count": cluster_count,
                "row_count": int(entry["row_count"]),
                "field_name": str(entry["field_name"]),
            }
        )

    out.sort(key=lambda x: (x["struct_path"], x["offset"], x["enum_path"]))
    return out
