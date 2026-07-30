#!/usr/bin/env python3
"""Create a new native runtime test: the source skeleton and its catalog entry.

Adding a test used to mean editing four places and getting the same four things right --
the .cpp, a declaration in a hand-maintained header, the catalog entry, and a file-static
instance plus factory function. The header is now generated, which leaves two: the source and
the catalog row. This writes both.

Scaffolding only. The generated skeleton is a starting point that the author then owns
outright -- nothing regenerates a test body, and there is no marker claiming otherwise.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Sequence

from tools.common.repo import repo_root_from_file
from tools.runtime.catalog import TESTS


# base name -> (scenario base class, header, what it gives you)
BASES: dict[str, tuple[str, str, str]] = {
    "easy-map": (
        "EasyMapScriptScenario",
        "RuntimeScriptBases.h",
        "a random game on Easy, already on the strategic map (no capital selection)",
    ),
    "introductory-map": (
        "IntroductoryMapScriptScenario",
        "RuntimeScriptBases.h",
        "a random game on Introductory, which also shows the opening newspaper",
    ),
    "combined-map": (
        "CombinedMapScriptScenario",
        "RuntimeScriptBases.h",
        "a random game on Normal or above, after the player picks a capital",
    ),
    "loaded-map": (
        "LoadedMapScriptScenario",
        "RuntimeScriptBases.h",
        "a saved game loaded from a fixture (requires IMPERIALISM_RUNTIME_TEST_FIXTURE)",
    ),
    "managers-ready": (
        "ManagersReadyScriptScenario",
        "RuntimeScriptBases.h",
        "managers only: no main window, no navigation, no screen",
    ),
}


def camel_case(name: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[^0-9A-Za-z]+", name) if part)


SOURCE_TEMPLATE = '''#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"

#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"

namespace {{

// TODO: say what this scenario proves and why it would matter if it broke.
//
// Start point: {base_description}.
//
// Reminders (see scenarios/RuntimeScriptMacros.h):
//   * anything that must survive a yield is a member field -- the compiler rejects an
//     initialized local whose scope spans a yield, which is the rule working for you;
//   * one RT_ macro per source line;
//   * never put an RT_ macro inside try/catch.
//
// Useful next steps:
//   just runtime-dev {test_name}          build only what changed, then run
//   just runtime-tree {test_name} --paths read the real tag hierarchy off a failed run
class {case_class} : public {base_class} {{
protected:
  void Script() override {{
    RT_BEGIN();

    RT_AWAIT_SCREEN(TMapUberPicture, kTurnEventStrategicMap);
    // TODO: actions, waits and assertions, in order.
    RT_PASS();

    RT_END();
  }}
}};

}} // namespace

RUNTIME_TEST_FACTORY({case_class}, {factory_name})
'''


def catalog_entry(test_name: str, factory_name: str) -> str:
    return (
        f"    RuntimeTestSpec(\n"
        f'        "{test_name}",\n'
        f'        "{factory_name}",\n'
        f'        ("full",),\n'
        f'        "internal_invariant",\n'
        # RuntimeTestSpec defaults required_oracles to ("ui",), which fails a skeleton that
        # requests no snapshots. Start with none and let the author add them with the
        # native_snapshots they actually capture.
        f"        required_oracles=(),\n"
        f"    ),\n"
    )


def insert_catalog_entry(repo: Path, test_name: str, factory_name: str) -> bool:
    path = repo / "tools" / "runtime" / "catalog.py"
    text = path.read_text(encoding="utf-8")
    if f'"{test_name}"' in text:
        return False
    # Append as the last element of the TESTS tuple, just before its closing paren.
    marker = "\n)\n"
    index = text.rindex("RuntimeTestSpec(")
    close = text.index(marker, index)
    insertion = catalog_entry(test_name, factory_name)
    path.write_text(text[: close + 1] + insertion + text[close + 1 :], encoding="utf-8")
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Registered test name, snake_case (e.g. city_screen_opens).")
    parser.add_argument(
        "--base",
        default="easy-map",
        choices=sorted(BASES),
        help="Where the script starts.",
    )
    parser.add_argument(
        "--factory",
        help="Factory/class stem (default: derived from the name, e.g. CityScreenOpens).",
    )
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[a-z][a-z0-9_]*", args.name):
        print(f"{args.name!r} is not a snake_case test name.")
        return 2

    repo = repo_root_from_file(__file__)
    base_class, _, base_description = BASES[args.base]
    stem = args.factory or camel_case(args.name)
    factory_name = f"{stem}Test"
    case_class = f"{stem}TestCase"
    source_path = repo / "tests" / "runtime" / "native" / "scenarios" / f"{factory_name}.cpp"

    if source_path.exists():
        print(f"{source_path.relative_to(repo)} already exists; not overwriting.")
        return 2
    if any(test.name == args.name for test in TESTS):
        print(f"{args.name!r} is already in the catalog.")
        return 2

    source_path.write_text(
        SOURCE_TEMPLATE.format(
            base_class=base_class,
            base_description=base_description,
            case_class=case_class,
            factory_name=factory_name,
            test_name=args.name,
        ),
        encoding="utf-8",
    )
    print(f"wrote {source_path.relative_to(repo)}")

    if insert_catalog_entry(repo, args.name, factory_name):
        print("added a catalog entry in tools/runtime/catalog.py (review its suites and evidence)")
    else:
        print("catalog already mentions this test; left tools/runtime/catalog.py alone")

    # Adding a .cpp changes the source set, so the next build needs a configure -- runtime-dev
    # detects that itself, but say so rather than letting it look like an unexplained slow build.
    print(f"next: just runtime-dev {args.name}   (a new file forces one CMake configure)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
