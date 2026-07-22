#!/usr/bin/env python3
"""Generate the turn-event-code coverage matrix (bd 1uj.58.5).

The normal path is source-only.  It joins the committed UI factory manifest,
ported TViewMgr dispatch/teardown source, constant event post/dispatch/dialog
callsites, the complete Mac View disposition inventory, and the committed
Ghidra callback snapshot.  It never starts the game or opens either retail
binary.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

from tools.common.file_scan import iter_files
from tools.common.repo import repo_root_from_file
from tools.source_model import build_model
from tools.ui_codegen import UiResourceKey, load_recipes, load_ui_views
from tools.workflow.ui_view_coverage import build_coverage_rows


FORMAT_VERSION = 1
CONFIG_PATH = "config/turn_event_coverage.yml"
REPORT_PATH = "docs/reference/turn-event-coverage.md"
CALLBACK_PATH = "docs/reference/ui_callback_audit.json"
DISPATCH_ADDRESS = 0x005D7240
EXIT_ADDRESS = 0x005DB620

_FUNCTION_RE = re.compile(r"^// FUNCTION: IMPERIALISM (0x[0-9a-fA-F]+)$", re.MULTILINE)
_EVENT_CALL_RE = re.compile(
    r"\b(?P<callee>PostTurnEventCodeMessage2420|DispatchTurnEvent|"
    r"ResolveTurnEventDialogNodeByMessageContext)\s*\(\s*"
    r"(?P<code>0x[0-9a-fA-F]+|[0-9]+)"
)
_CASE_RE = re.compile(r"\bcase\s+(0x[0-9a-fA-F]+|[0-9]+)\s*:")
_METHOD_CALL_RE = re.compile(r"\b(this|[A-Za-z_]\w*)->([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class SourceSection:
    address: int
    name: str
    path: str
    marker_line: int
    body: str


@dataclass(frozen=True)
class EventReference:
    event: int
    kind: str
    sender: str
    evidence: str


def _hex_event(event: int) -> str:
    return f"0x{event:04x}"


def _load_config(repo_root: Path) -> tuple[dict[int, dict], dict[int, str], dict[int, str]]:
    data = yaml.safe_load((repo_root / CONFIG_PATH).read_text(encoding="utf-8"))
    if data.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"{CONFIG_PATH}: unsupported format_version")
    boot = {int(key): dict(value) for key, value in data.get("boot_path", {}).items()}
    names = {int(key): str(value) for key, value in data.get("screen_names", {}).items()}
    gaps = {int(key): str(value) for key, value in data.get("gap_owners", {}).items()}
    return boot, names, gaps


def source_sections(repo_root: Path) -> list[SourceSection]:
    model = build_model(repo_root)
    sections: list[SourceSection] = []
    for path in iter_files([str(repo_root / "src" / "game")], patterns=("*.cpp",)):
        source = path.read_text(encoding="utf-8", errors="replace")
        markers = list(_FUNCTION_RE.finditer(source))
        for index, marker in enumerate(markers):
            address = int(marker.group(1), 0)
            end = markers[index + 1].start() if index + 1 < len(markers) else len(source)
            claim = model.functions.get(address)
            name = claim.name if claim is not None and claim.name else f"sub_{address:08x}"
            sections.append(
                SourceSection(
                    address,
                    name,
                    path.relative_to(repo_root).as_posix(),
                    source.count("\n", 0, marker.start()) + 1,
                    source[marker.end() : end],
                )
            )
    return sections


def scan_event_references(sections: list[SourceSection]) -> list[EventReference]:
    references: list[EventReference] = []
    for section in sections:
        for match in _EVENT_CALL_RE.finditer(section.body):
            event = int(match.group("code"), 0)
            callee = match.group("callee")
            if callee == "ResolveTurnEventDialogNodeByMessageContext":
                kind = "dialog_open"
            elif callee == "PostTurnEventCodeMessage2420":
                kind = "post"
            else:
                kind = "dispatch"
            line = section.marker_line + section.body.count("\n", 0, match.start()) + 1
            references.append(
                EventReference(
                    event,
                    kind,
                    f"{section.name} ({section.path}:{line})",
                    f"{callee}({_hex_event(event)})",
                )
            )
    return sorted(references, key=lambda row: (row.event, row.kind, row.sender))


def _balanced_region(text: str, start: int, opener: str, closer: str) -> tuple[str, int]:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opener:
            depth += 1
        elif text[index] == closer:
            depth -= 1
            if depth == 0:
                return text[start + 1 : index], index + 1
    raise ValueError(f"unbalanced {opener}{closer} region")


def _method_calls(text: str) -> list[str]:
    return sorted({f"{match.group(1)}->{match.group(2)}" for match in _METHOD_CALL_RE.finditer(text)})


def conditional_hooks(text: str, variable: str) -> dict[int, set[str]]:
    """Extract direct method calls from explicit ``variable == constant`` branches."""
    hooks: dict[int, set[str]] = defaultdict(set)
    pattern = re.compile(r"\b(?:if|else\s+if)\s*\(")
    position = 0
    equality = re.compile(rf"\b{re.escape(variable)}\s*==\s*(0x[0-9a-fA-F]+|[0-9]+)")
    while True:
        match = pattern.search(text, position)
        if match is None:
            break
        paren = text.find("(", match.start())
        condition, after_condition = _balanced_region(text, paren, "(", ")")
        codes = [int(value, 0) for value in equality.findall(condition)]
        brace = text.find("{", after_condition)
        if not codes or brace < 0:
            position = after_condition
            continue
        branch, after_branch = _balanced_region(text, brace, "{", "}")
        calls = _method_calls(branch)
        for code in codes:
            hooks[code].update(calls)
        position = after_branch
    return hooks


def switch_hooks(text: str) -> dict[int, set[str]]:
    """Extract method calls from case-labelled blocks in a selected switch segment."""
    hooks: dict[int, set[str]] = defaultdict(set)
    pending: list[int] = []
    for line in text.splitlines():
        cases = [int(value, 0) for value in _CASE_RE.findall(line)]
        if cases:
            pending.extend(cases)
        if pending:
            calls = _method_calls(line)
            for code in pending:
                hooks[code].update(calls)
        if pending and re.search(r"\b(?:break|return)\s*;", line):
            pending = []
        if re.search(r"\bdefault\s*:", line):
            pending = []
    return hooks


def _merge_hooks(*maps: dict[int, set[str]]) -> dict[int, list[str]]:
    merged: dict[int, set[str]] = defaultdict(set)
    for mapping in maps:
        for event, hooks in mapping.items():
            merged[event].update(hooks)
    return {event: sorted(hooks) for event, hooks in merged.items()}


def dispatch_hooks(dispatch_body: str) -> tuple[dict[int, list[str]], dict[int, list[str]]]:
    teardown_start = dispatch_body.index("// Teardown hook")
    teardown_end = dispatch_body.index("// Code 0 =", teardown_start)
    same_start = dispatch_body.index("// Same-code refresh")
    same_end = dispatch_body.index("// Cross-code path", same_start)
    cross_start = same_end
    cross_end = dispatch_body.index("DispatchPostTurnStateUpdatesTail();", cross_start)
    teardown = dispatch_body[teardown_start:teardown_end]
    same = dispatch_body[same_start:same_end]
    cross = dispatch_body[cross_start:cross_end]
    hooks = _merge_hooks(
        conditional_hooks(dispatch_body[teardown_end:same_start], "newCode"),
        conditional_hooks(same, "newCode"),
        conditional_hooks(cross, "newCode"),
        switch_hooks(cross),
    )
    teardown_hooks = _merge_hooks(switch_hooks(teardown))
    return hooks, teardown_hooks


def exit_state_senders(exit_body: str) -> dict[int, list[str]]:
    senders: dict[int, set[str]] = defaultdict(set)
    pending_modes: list[int] = []
    for line in exit_body.splitlines():
        cases = [int(value, 0) for value in _CASE_RE.findall(line)]
        if cases:
            pending_modes.extend(cases)
        match = re.search(r"PostTurnEventCodeMessage2420\s*\(\s*(0x[0-9a-fA-F]+|[0-9]+)", line)
        if match:
            event = int(match.group(1), 0)
            mode_text = ", ".join(_hex_event(mode) for mode in pending_modes) or "conditional"
            senders[event].add(f"TViewMgr::HandleTurnStateExitAndPostFollowupEventCode modes {mode_text}")
        if re.search(r"\breturn\s*;", line):
            pending_modes = []
        if re.search(r"\bdefault\s*:", line):
            pending_modes = []
    return {event: sorted(values) for event, values in senders.items()}


def build_rows(repo_root: Path) -> tuple[list[dict], list[dict], dict]:
    boot, screen_names, gap_owners = _load_config(repo_root)
    sections = source_sections(repo_root)
    by_address = {section.address: section for section in sections}
    if DISPATCH_ADDRESS not in by_address or EXIT_ADDRESS not in by_address:
        raise ValueError("ported TViewMgr dispatch/exit source sections are missing")
    hooks, teardown = dispatch_hooks(by_address[DISPATCH_ADDRESS].body)
    exit_senders = exit_state_senders(by_address[EXIT_ADDRESS].body)
    references = scan_event_references(sections)
    refs_by_event: dict[int, list[EventReference]] = defaultdict(list)
    for reference in references:
        refs_by_event[reference.event].append(reference)

    views = load_ui_views(repo_root)
    factories: dict[int, list[dict]] = defaultdict(list)
    for recipe in load_recipes(repo_root):
        for case in recipe.cases:
            if case.resource is not None:
                view = views[case.resource]
                identity = str(view.get("view_name") or case.resource.text())
                resource = case.resource.text()
                platform = "mac_resource"
            elif case.windows_view:
                identity = case.windows_view
                resource = "-"
                platform = "windows_only"
            else:
                identity = case.rejected
                resource = "-"
                platform = "rejected"
            factories[case.event].append(
                {
                    "address": recipe.address,
                    "name": recipe.name,
                    "resource": resource,
                    "identity": identity,
                    "platform": platform,
                    "evidence": case.evidence,
                }
            )

    events = set(factories) | set(refs_by_event) | set(hooks) | set(teardown) | set(boot)
    rows: list[dict] = []
    for event in sorted(events):
        event_refs = refs_by_event.get(event, [])
        senders = sorted(
            {ref.sender for ref in event_refs if ref.kind in ("post", "dispatch")}
            | set(exit_senders.get(event, []))
        )
        dialogs = sorted({ref.sender for ref in event_refs if ref.kind == "dialog_open"})
        factory_rows = factories.get(event, [])
        identities = sorted(
            {factory["identity"] for factory in factory_rows}
            | ({screen_names[event]} if event in screen_names else set())
        )
        if factory_rows and (senders or dialogs or event in boot):
            status = "implemented_reachable"
        elif factory_rows:
            status = "implemented_apparently_unreachable"
        elif senders or dialogs:
            status = "posted_missing_builder"
        elif event == 0:
            status = "internal_dispatch"
        else:
            status = "dispatch_only_unknown"
        boot_row = boot.get(event)
        gap_bead = gap_owners.get(event, "")
        if boot_row is not None and status not in ("implemented_reachable", "internal_dispatch"):
            gap_bead = str(boot_row["gap_bead"])
        rows.append(
            {
                "event": event,
                "status": status,
                "boot_stage": str(boot_row["stage"]) if boot_row else "",
                "gap_bead": gap_bead,
                "identities": identities,
                "factories": factory_rows,
                "senders": senders,
                "dialogs": dialogs,
                "hooks": hooks.get(event, []),
                "teardown": teardown.get(event, []),
            }
        )

    coverage_rows, coverage_errors = build_coverage_rows(repo_root)
    if coverage_errors:
        raise ValueError("Mac View coverage errors: " + "; ".join(coverage_errors))
    generated_resources = {
        factory["resource"]
        for rows_for_event in factories.values()
        for factory in rows_for_event
        if factory["resource"] != "-"
    }
    mac_complement = [
        {
            "resource": row.key.text(),
            "name": row.name,
            "status": row.status,
            "owner": row.owner,
            "bead": row.bead,
        }
        for row in coverage_rows
        if row.key.text() not in generated_resources
    ]

    callback_report = json.loads((repo_root / CALLBACK_PATH).read_text(encoding="utf-8"))
    if callback_report.get("format_version") != 1:
        raise ValueError(f"{CALLBACK_PATH}: unsupported format_version")
    return rows, mac_complement, callback_report


def _cell(values: list[str]) -> str:
    return "<br>".join(value.replace("|", "\\|") for value in values) if values else "-"


def render_report(rows: list[dict], mac_complement: list[dict], callbacks: dict) -> str:
    counts = Counter(row["status"] for row in rows)
    boot_rows = [row for row in rows if row["boot_stage"]]
    unresolved_boot = [row for row in boot_rows if row["gap_bead"]]
    callback_by_address = {row["target"]: row for row in callbacks["targets"]}
    unowned_large_callbacks = [
        callback_by_address[address]
        for address in callbacks["ranked_candidates"]
        if address in callback_by_address
        and not callback_by_address[address]["owner"]
        and int(callback_by_address[address]["size"]) > 32
    ]
    lines = [
        "<!-- AUTO-GENERATED by tools/workflow/turn_event_coverage.py; DO NOT EDIT. -->",
        "# Turn-event UI coverage",
        "",
        "This matrix is generated entirely from committed source/evidence. It joins the 17",
        "turn-event factories, `TViewMgr::DispatchTurnEvent` hooks and teardown cases, the",
        "turn-state-exit posts, constant event post/dispatch/dialog callsites, the complete",
        "Mac View disposition inventory, and the Ghidra-derived callback snapshot. Normal",
        "checks do not launch the game or open a retail binary.",
        "",
        "## Summary",
        "",
        f"- Event codes: {len(rows)}",
        f"- Boot-path stages: {len(boot_rows)}; unresolved: {len(unresolved_boot)}",
    ]
    for status in sorted(counts):
        lines.append(f"- `{status}`: {counts[status]}")
    lines.extend(
        (
            "",
            "## Event matrix",
            "",
            "| Code | Status | Screen/resource | Factory | Sender or opener | Dispatch hook | Teardown | Boot/gap |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        )
    )
    for row in rows:
        factories = [
            f"0x{factory['address']:08x} {factory['name']} [{factory['resource']}]"
            for factory in row["factories"]
        ]
        senders = row["senders"] + [f"dialog: {sender}" for sender in row["dialogs"]]
        boot = row["boot_stage"]
        if row["gap_bead"]:
            boot = f"{boot} -> `{row['gap_bead']}`" if boot else f"`{row['gap_bead']}`"
        lines.append(
            f"| `{_hex_event(row['event'])}` | `{row['status']}` | "
            f"{_cell(row['identities'])} | {_cell(factories)} | {_cell(senders)} | "
            f"{_cell(row['hooks'])} | {_cell(row['teardown'])} | {boot or '-'} |"
        )

    lines.extend(
        (
            "",
            "## Mac View complement",
            "",
            "Generated factory resources are represented in the event matrix above. These are",
            "the remaining committed Mac Views and their explicit Windows disposition.",
            "",
            "| Resource | Name | Status | Owner/disposition | Bead |",
            "| --- | --- | --- | --- | --- |",
        )
    )
    for row in mac_complement:
        lines.append(
            f"| `{row['resource']}` | {row['name']} | `{row['status']}` | "
            f"{row['owner'].replace('|', '\\|')} | `{row['bead']}` |"
        )

    validation = callbacks["validation"]
    lines.extend(
        (
            "",
            "## Hidden callback audit",
            "",
            f"The binary scan found all {validation['startup_factories']['found']}/"
            f"{validation['startup_factories']['expected']} startup factory registrations. "
            "It also found `0x00484230`, now correctly classified as an MFC message-map "
            "handler rather than raw callback debt.",
            "",
        )
    )
    if not unowned_large_callbacks:
        lines.append("No UI-relevant unowned callback candidate larger than 32 bytes remains.")
    else:
        lines.extend(("| Target | Name | Size | Registrars |", "| --- | --- | ---: | --- |"))
        for row in unowned_large_callbacks:
            lines.append(
                f"| `{row['target']}` | {row['name']} | {row['size']} | "
                f"{_cell(row['registrars'])} |"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="rewrite the committed report")
    action.add_argument("--check", action="store_true", help="fail if the report is stale")
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=2)
    try:
        rows, mac_complement, callbacks = build_rows(repo_root)
        report = render_report(rows, mac_complement, callbacks)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"Turn-event coverage failed: {exc}")
        return 1
    report_path = repo_root / REPORT_PATH
    if args.write:
        report_path.write_text(report, encoding="utf-8")
        print(f"Wrote {REPORT_PATH}: {len(rows)} event codes")
        return 0
    if args.check:
        current = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
        if current != report:
            print(f"Turn-event coverage failed: {REPORT_PATH} is stale; run with --write")
            return 1
        print(f"Turn-event coverage passed: {len(rows)} event codes")
        return 0
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
