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
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from tools.common.repo import repo_root_from_file
from tools.runtime.catalog import TESTS


# Every base hands the script a *different* starting world, so they cannot share one skeleton:
# a managers-ready scenario has no screen to wait for, and a loaded-map scenario refuses to run
# without a fixture. `body` is what goes between RT_BEGIN() and RT_PASS().
@dataclass(frozen=True)
class BaseSpec:
    scenario_class: str
    description: str
    includes: tuple[str, ...]
    body: tuple[str, ...]
    requires_fixture: bool = False


# The map bases all hand over *after* their checkpoint, so the script already starts on the
# strategic map. Waiting for it again is redundant, and no scenario in the tree does.
_ON_THE_MAP: tuple[str, ...] = (
    "// The base hands over once the strategic map is ready, so the script starts there.",
    "// TODO: actions, waits and assertions, in order.",
)

_MAP_INCLUDES: tuple[str, ...] = ('#include "screens/StrategicMapScreen.h"',)


BASES: dict[str, BaseSpec] = {
    "easy-map": BaseSpec(
        "EasyMapScriptScenario",
        "a random game on Easy, already on the strategic map (no capital selection)",
        _MAP_INCLUDES,
        _ON_THE_MAP,
    ),
    "introductory-map": BaseSpec(
        "IntroductoryMapScriptScenario",
        "a random game on Introductory, which also shows the opening newspaper",
        _MAP_INCLUDES,
        _ON_THE_MAP,
    ),
    "combined-map": BaseSpec(
        "CombinedMapScriptScenario",
        "a random game on Normal or above, after the player picks a capital",
        _MAP_INCLUDES,
        _ON_THE_MAP,
    ),
    "loaded-map": BaseSpec(
        "LoadedMapScriptScenario",
        "a saved game loaded from a fixture",
        _MAP_INCLUDES,
        (
            "// LoadGameFlow has loaded the fixture and handed over on the strategic map.",
            "// TODO: assert on what the *loaded* state must be -- that is the point of this base.",
        ),
        requires_fixture=True,
    ),
    "managers-ready": BaseSpec(
        "ManagersReadyScriptScenario",
        "managers only: no main window, no navigation, no screen",
        (),
        (
            "// No window, no navigation, no screen: assert on model state directly, and include",
            "// the game headers those assertions need.",
            "// TODO: assertions.",
        ),
    ),
}


def camel_case(name: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[^0-9A-Za-z]+", name) if part)


SOURCE_TEMPLATE = '''#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
{includes}
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

{body}
    RT_PASS();

    RT_END();
  }}
}};

}} // namespace

RUNTIME_TEST_FACTORY({case_class}, {factory_name})
'''


def catalog_entry(test_name: str, factory_name: str, fixture: str | None) -> str:
    # A fixture-backed scenario is a retail oracle by construction: the bytes come from outside
    # this build, which is the whole reason LoadedMapScriptScenario enforces their presence.
    evidence = "retail_fixture_oracle" if fixture else "internal_invariant"
    entry = (
        f"    RuntimeTestSpec(\n"
        f'        "{test_name}",\n'
        f'        "{factory_name}",\n'
        f'        ("full",),\n'
        f'        "{evidence}",\n'
    )
    if fixture:
        entry += (
            f"        fixture=RuntimeFixtureSpec(\n"
            f'            "{fixture}", "{evidence}"\n'
            f"        ),\n"
        )
    # RuntimeTestSpec defaults required_oracles to ("ui",), which fails a skeleton that
    # requests no snapshots. Start with none and let the author add them with the
    # native_snapshots they actually capture.
    entry += f"        required_oracles=(),\n" f"    ),\n"
    return entry


def insert_catalog_entry(
    repo: Path, test_name: str, factory_name: str, fixture: str | None
) -> bool:
    path = repo / "tools" / "runtime" / "catalog.py"
    text = path.read_text(encoding="utf-8")
    if f'"{test_name}"' in text:
        return False
    # Append as the last element of the TESTS tuple, just before its closing paren.
    marker = "\n)\n"
    index = text.rindex("RuntimeTestSpec(")
    close = text.index(marker, index)
    insertion = catalog_entry(test_name, factory_name, fixture)
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
    parser.add_argument(
        "--fixture",
        help="Save fixture filename under tests/runtime/fixtures (required by --base loaded-map).",
    )
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[a-z][a-z0-9_]*", args.name):
        print(f"{args.name!r} is not a snake_case test name.")
        return 2

    repo = repo_root_from_file(__file__)
    base = BASES[args.base]

    # LoadedMapScriptScenario::RequiresFixture() is enforced by the harness, so a fixture-less
    # entry for that base cannot run at all. Refuse to scaffold one rather than emit a test that
    # is dead on arrival.
    if base.requires_fixture and not args.fixture:
        print(f"--base {args.base} needs --fixture FILE (a save under tests/runtime/fixtures).")
        return 2
    if args.fixture and not base.requires_fixture:
        print(f"--fixture only applies to a base that loads one; --base {args.base} does not.")
        return 2
    if args.fixture:
        fixture_path = repo / "tests" / "runtime" / "fixtures" / args.fixture
        if not fixture_path.is_file():
            # A warning, not an error: scaffolding the test before producing its save is a
            # reasonable order to work in, and `--require-fixtures` is what enforces presence.
            print(f"note: {fixture_path.relative_to(repo)} does not exist yet")

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

    # The template already carries the blank line before `namespace`, so each include just
    # terminates its own line; an empty tuple must leave no stray blank.
    includes = "".join(f"{line}\n" for line in base.includes)
    source_path.write_text(
        SOURCE_TEMPLATE.format(
            base_class=base.scenario_class,
            base_description=base.description,
            body="\n".join(f"    {line}" for line in base.body),
            case_class=case_class,
            factory_name=factory_name,
            includes=includes,
            test_name=args.name,
        ),
        encoding="utf-8",
    )
    print(f"wrote {source_path.relative_to(repo)}")

    if insert_catalog_entry(repo, args.name, factory_name, args.fixture):
        print("added a catalog entry in tools/runtime/catalog.py (review its suites and evidence)")
    else:
        print("catalog already mentions this test; left tools/runtime/catalog.py alone")

    # Adding a .cpp changes the source set, so the next build needs a configure -- runtime-dev
    # detects that itself, but say so rather than letting it look like an unexplained slow build.
    print(f"next: just runtime-dev {args.name}   (a new file forces one CMake configure)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
