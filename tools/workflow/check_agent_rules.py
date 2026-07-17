#!/usr/bin/env python3
"""Lint config/agent_rules.yml — the structured agent rule knowledge base.

Rejects:
  - duplicate rule ids, or ids not matching <AREA>-<NAME>-<NNN>;
  - out-of-order numeric suffixes within the file (append-only discipline);
  - superseded rules without a `superseded_by` pointing at an existing ACTIVE rule;
  - a rule both requiring and forbidding the same action token;
  - `tools:` entries that are not `just ...` commands (raw module runs re-teach the
    wrong habit — Hard Rule 2);
  - trigger tags that no other rule shares AND the advice engine cannot derive
    (unknown tags silently never fire).

Also cross-checks that every `skill:` reference names an existing skill directory.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_YML = REPO_ROOT / "config" / "agent_rules.yml"
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
ADVICE_PY = REPO_ROOT / "tools" / "workflow" / "advice.py"

ID_RE = re.compile(r"^[A-Z]+-[A-Z0-9]+-(\d{3})$")


def derivable_tags() -> set[str]:
    """Tags the advice engine can actually produce (string literals in advice.py)."""
    text = ADVICE_PY.read_text(encoding="utf-8")
    tags = set(re.findall(r'"([a-z][a-z0-9_]+)"\)', text))
    tags |= set(re.findall(r'tags\.add\("([a-z0-9_]+)"\)', text))
    tags |= set(re.findall(r'tags = \{([^}]*)\}', text) and
                re.findall(r'"([a-z0-9_]+)"', " ".join(re.findall(r'tags = \{([^}]*)\}', text))))
    return tags


def main() -> int:
    data = yaml.safe_load(RULES_YML.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    failures: list[str] = []

    seen: dict[str, int] = {}
    last_num = 0
    active_ids = {r.get("id") for r in rules if r.get("status") == "active"}
    known_skills = {p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}
    known_tags = derivable_tags()

    for idx, rule in enumerate(rules):
        rid = rule.get("id", f"<rule #{idx}>")
        m = ID_RE.match(rid)
        if not m:
            failures.append(f"{rid}: id does not match <AREA>-<NAME>-<NNN>")
            continue
        if rid in seen:
            failures.append(f"{rid}: duplicate id (first at index {seen[rid]})")
        seen[rid] = idx
        num = int(m.group(1))
        if num < last_num:
            failures.append(f"{rid}: numeric suffix {num:03d} out of order "
                            f"(previous {last_num:03d}) — ids are append-only")
        last_num = max(last_num, num)

        status = rule.get("status")
        if status not in ("active", "superseded"):
            failures.append(f"{rid}: status must be active|superseded, got {status!r}")
        if status == "superseded":
            succ = rule.get("superseded_by")
            if not succ:
                failures.append(f"{rid}: superseded without superseded_by")
            elif succ not in active_ids:
                failures.append(f"{rid}: superseded_by {succ!r} is not an active rule")

        required = set(rule.get("required") or [])
        forbidden = set(rule.get("forbidden") or [])
        overlap = required & forbidden
        if overlap:
            failures.append(f"{rid}: required and forbidden overlap: {sorted(overlap)}")

        for tool in rule.get("tools") or []:
            if not str(tool).startswith("just "):
                failures.append(f"{rid}: tool {tool!r} is not a `just` command "
                                "(Hard Rule 2: tools teach just targets)")

        skill = rule.get("skill")
        if skill and skill not in known_skills:
            failures.append(f"{rid}: skill {skill!r} does not exist under .claude/skills/")

        if status == "active":
            for tag in rule.get("triggers") or []:
                if tag not in known_tags:
                    failures.append(f"{rid}: trigger {tag!r} is not derivable by "
                                    "tools/workflow/advice.py (it would never fire) — "
                                    "add a derivation or fix the tag")

    if failures:
        print("Agent-rules KB lint failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"Agent-rules KB lint passed ({len(rules)} rules, "
          f"{len(active_ids)} active, {len(known_tags)} derivable tags).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
