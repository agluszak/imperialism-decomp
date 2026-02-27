from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

DEFAULT_CANONICAL_PROJECT_ROOT = "/imperialism"
DEFAULT_LEGACY_PROJECT_ROOTS = ("/Imperialism",)


def normalize_root_path(root: str) -> str:
    txt = (root or "").strip()
    if not txt:
        raise ValueError("root path cannot be empty")
    if not txt.startswith("/"):
        txt = "/" + txt
    if len(txt) > 1 and txt.endswith("/"):
        txt = txt.rstrip("/")
    return txt


def parse_roots_csv(raw: str | None) -> list[str]:
    if raw is None:
        return []
    seen: OrderedDict[str, None] = OrderedDict()
    for part in str(raw).split(","):
        p = part.strip()
        if not p:
            continue
        seen[normalize_root_path(p)] = None
    return list(seen.keys())


def project_category_path(*parts: str) -> str:
    out = DEFAULT_CANONICAL_PROJECT_ROOT
    for part in parts:
        p = (part or "").strip().strip("/")
        if not p:
            continue
        out = out.rstrip("/") + "/" + p
    return normalize_root_path(out)


def project_datatype_path(name: str, *parts: str) -> str:
    return build_datatype_path(project_category_path(*parts), name)


def require_project_category_path(category_path: str) -> str:
    canonical = canonicalize_category_path(
        category_path,
        canonical_root=DEFAULT_CANONICAL_PROJECT_ROOT,
        source_roots=(DEFAULT_CANONICAL_PROJECT_ROOT, *DEFAULT_LEGACY_PROJECT_ROOTS),
    )
    if not category_is_under_root(canonical, DEFAULT_CANONICAL_PROJECT_ROOT):
        raise ValueError(
            f"project datatype category must be under {DEFAULT_CANONICAL_PROJECT_ROOT}: {category_path!r}"
        )
    return canonical


def category_is_under_root(category_path: str, root: str) -> bool:
    cat = normalize_root_path(category_path)
    r = normalize_root_path(root)
    if r == "/":
        return True
    return cat == r or cat.startswith(r + "/")


def category_root_of(category_path: str, roots: Iterable[str]) -> str | None:
    normalized_roots = [normalize_root_path(r) for r in roots]
    normalized_roots.sort(key=len, reverse=True)
    for root in normalized_roots:
        if category_is_under_root(category_path, root):
            return root
    return None


def remap_category_root(category_path: str, src_root: str, dst_root: str) -> str:
    cat = normalize_root_path(category_path)
    src = normalize_root_path(src_root)
    dst = normalize_root_path(dst_root)
    if not category_is_under_root(cat, src):
        return cat
    suffix = cat[len(src) :]
    if not suffix:
        return dst
    return dst + suffix


def canonicalize_category_path(
    category_path: str,
    canonical_root: str = DEFAULT_CANONICAL_PROJECT_ROOT,
    source_roots: Iterable[str] = DEFAULT_LEGACY_PROJECT_ROOTS,
) -> str:
    cat = normalize_root_path(category_path)
    dst = normalize_root_path(canonical_root)
    for src in [normalize_root_path(x) for x in source_roots]:
        if src == "/":
            continue
        if category_is_under_root(cat, src):
            return remap_category_root(cat, src, dst)
    return cat


def split_datatype_path(datatype_path: str) -> tuple[str, str]:
    path = (datatype_path or "").strip()
    if not path:
        raise ValueError("datatype path is empty")
    if not path.startswith("/"):
        path = "/" + path
    if path == "/":
        raise ValueError("datatype path must include a name")
    idx = path.rfind("/")
    if idx <= 0:
        return "/", path[idx + 1 :]
    category = path[:idx]
    name = path[idx + 1 :]
    if not name:
        raise ValueError(f"datatype path missing name: {datatype_path!r}")
    return category, name


def build_datatype_path(category: str, name: str) -> str:
    cat = normalize_root_path(category)
    nm = (name or "").strip()
    if not nm:
        raise ValueError("datatype name is empty")
    if cat == "/":
        return "/" + nm
    return cat + "/" + nm


def alias_datatype_paths(
    datatype_path: str,
    canonical_root: str = DEFAULT_CANONICAL_PROJECT_ROOT,
    legacy_roots: Iterable[str] = DEFAULT_LEGACY_PROJECT_ROOTS,
) -> list[str]:
    category, name = split_datatype_path(datatype_path)
    roots = [normalize_root_path(canonical_root)] + [normalize_root_path(r) for r in legacy_roots]
    out: OrderedDict[str, None] = OrderedDict()
    for root in roots:
        remapped = remap_category_root(category, normalize_root_path(canonical_root), root)
        out[build_datatype_path(remapped, name)] = None
    out[build_datatype_path(category, name)] = None
    return list(out.keys())


def resolve_datatype_by_path_or_legacy_aliases(
    dtm,
    datatype_path: str,
    canonical_root: str = DEFAULT_CANONICAL_PROJECT_ROOT,
    legacy_roots: Iterable[str] = DEFAULT_LEGACY_PROJECT_ROOTS,
):
    for p in alias_datatype_paths(datatype_path, canonical_root=canonical_root, legacy_roots=legacy_roots):
        dt = dtm.getDataType(p)
        if dt is not None:
            return dt
    return None


def datatype_richness_tuple(dt) -> tuple[int, int, int, int, int]:
    components = 0
    enum_members = 0
    fn_args = 0
    length = 0

    try:
        components = int(dt.getNumComponents())
    except Exception:
        components = 0
    try:
        enum_members = int(dt.getCount())
    except Exception:
        enum_members = 0
    try:
        fn_args = len(list(dt.getArguments()))
    except Exception:
        fn_args = 0
    try:
        length = int(dt.getLength())
    except Exception:
        length = 0

    if components > 0:
        kind_rank = 4
    elif enum_members > 0:
        kind_rank = 3
    elif fn_args > 0:
        kind_rank = 2
    else:
        kind_rank = 1
    return (kind_rank, components, enum_members, fn_args, max(0, length))


def compare_datatype_richness(lhs, rhs) -> int:
    a = datatype_richness_tuple(lhs)
    b = datatype_richness_tuple(rhs)
    if a > b:
        return 1
    if a < b:
        return -1
    return 0


def collect_root_policy_violations(
    dtm,
    *,
    canonical_root: str = DEFAULT_CANONICAL_PROJECT_ROOT,
    forbidden_roots: Iterable[str] = DEFAULT_LEGACY_PROJECT_ROOTS,
) -> list[dict[str, str]]:
    canonical = normalize_root_path(canonical_root)
    forbidden = [normalize_root_path(r) for r in forbidden_roots if normalize_root_path(r) != canonical]
    out: list[dict[str, str]] = []
    if not forbidden:
        return out

    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        try:
            cat = str(dt.getCategoryPath().getPath())
            bad_root = next((r for r in forbidden if category_is_under_root(cat, r)), None)
            if bad_root is None:
                continue
            out.append(
                {
                    "full_path": str(dt.getPathName()),
                    "category_path": cat,
                    "forbidden_root": bad_root,
                    "canonical_root": canonical,
                }
            )
        except Exception:
            continue
    return out


def find_named_data_type(
    dtm,
    base_name: str,
    preferred_categories: Iterable[str] | None = None,
):
    target = (base_name or "").strip()
    if not target:
        return None

    if preferred_categories is None:
        preferred = [
            "/imperialism/classes",
            "/imperialism/types",
            "/Imperialism/classes",
            "/Imperialism/types",
            "/",
        ]
    else:
        preferred = [normalize_root_path(x) for x in preferred_categories]

    def category_priority(cat: str) -> int:
        for i, p in enumerate(preferred):
            if category_is_under_root(cat, p):
                return i
        return len(preferred) + 1

    best = None
    best_score = None
    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        try:
            if dt.getName() != target:
                continue
            cat = str(dt.getCategoryPath().getPath())
            richness = datatype_richness_tuple(dt)
            score = (
                category_priority(cat),
                -richness[0],
                -richness[1],
                -richness[2],
                -richness[3],
                -richness[4],
                len(cat),
                cat,
            )
            if best is None or score < best_score:
                best = dt
                best_score = score
        except Exception:
            continue
    return best
