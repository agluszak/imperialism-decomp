"""Original compiler-emission evidence, separate from authored source claims.

The catalog seeds the disposable symbols overlay. It never creates a C++ API;
addresses lacking an unambiguous identity still suppress stub generation. Legacy
labels are inherited reconstruction hypotheses, not independent original symbols.
"""

from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_table

CATALOG = "config/compiler_emissions.csv"


@dataclass(frozen=True)
class Emission:
    address: int
    name: str
    symbol: str
    prototype: str
    kind: str
    file: str


def load_emissions(repo_root: Path) -> dict[int, Emission]:
    path = repo_root / CATALOG
    if not path.is_file():
        return {}
    _, rows = read_pipe_table(path)
    identities = {}
    for row in rows:
        address = int(row["address"], 16)
        kind = row["type"].lower()
        if address <= 0 or kind not in {"synthetic", "template"}:
            raise ValueError(f"Invalid emission identity at {address:#x}")
        if address in identities:
            raise ValueError(f"Duplicate emission identity at {address:#x}")
        identities[address] = Emission(
            address,
            row["name"],
            row["symbol"],
            row["prototype"],
            kind,
            row.get("source_file", ""),
        )
    return identities
