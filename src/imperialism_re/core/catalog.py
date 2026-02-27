from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CommandSpec:
    name: str
    module: str
    mode: str
    status: str
    summary: str



def _catalog_path() -> Path:
    return Path(__file__).resolve().parents[1] / "command_catalog.yaml"



def load_catalog() -> list[CommandSpec]:
    path = _catalog_path()
    lines = path.read_text(encoding="utf-8").splitlines()

    items: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in lines:
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.strip() == "commands:":
            continue
        if line.startswith("  - "):
            if current is not None:
                items.append(current)
            current = {}
            key, _, value = line[4:].partition(":")
            current[key.strip()] = value.strip()
            continue
        if line.startswith("    ") and current is not None:
            key, _, value = line.strip().partition(":")
            current[key.strip()] = value.strip()
            continue

    if current is not None:
        items.append(current)

    out: list[CommandSpec] = []
    for it in items:
        out.append(
            CommandSpec(
                name=it["name"],
                module=it["module"],
                mode=it["mode"],
                status=it["status"],
                summary=it.get("summary", ""),
            )
        )
    return out



def catalog_map() -> dict[str, CommandSpec]:
    return {cmd.name: cmd for cmd in load_catalog()}
