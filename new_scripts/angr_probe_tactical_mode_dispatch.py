#!/usr/bin/env python3
"""
Targeted angr+claripy probe for tactical mode dispatch semantics.

What it does:
1) Builds a function-scoped CFGEmulated for RunTacticalAutoTurnControllerForActiveUnit.
2) Computes CDG/DDG and a BackwardSlice for the mode read site.
3) Decodes compare blocks that gate secondary-pass dispatch and extracts allowed mode constants.
4) Uses claripy to model the predicate and enumerate satisfying values in a small domain.

Usage:
  .venv/bin/python new_scripts/angr_probe_tactical_mode_dispatch.py <exe_path> [out_json]
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import angr
import claripy

# Known tactical auto-turn anchors in Imperialism.exe
FUNC_ADDR = 0x0059E4F0
MODE_READ_ADDR = 0x0059E573
MODE_CMP_ADDRS = (0x0059E76C, 0x0059E771, 0x0059E776)
SECONDARY_PASS_BLOCK = 0x0059E77B


def parse_imm_from_cmp(insn_text: str) -> int | None:
    # Expected capstone form: "cmp eax, 0xe" / "cmp eax, 5" / "cmp eax, 2"
    txt = insn_text.strip().lower()
    if not txt.startswith("cmp "):
        return None
    parts = txt.split(",", 1)
    if len(parts) != 2:
        return None
    rhs = parts[1].strip()
    try:
        if rhs.startswith("0x"):
            return int(rhs, 16)
        return int(rhs, 10)
    except Exception:
        return None


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: .venv/bin/python new_scripts/angr_probe_tactical_mode_dispatch.py "
            "<exe_path> [out_json]"
        )
        return 1

    exe_path = Path(sys.argv[1]).resolve()
    if not exe_path.exists():
        print(f"missing exe: {exe_path}")
        return 1
    out_json = (
        Path(sys.argv[2]).resolve()
        if len(sys.argv) >= 3
        else Path("tmp_decomp/campaign_state_machine/outputs/tactical_mode_dispatch_probe.json").resolve()
    )

    # Keep angr logs readable for scripted runs.
    for name in (
        "angr.state_plugins.unicorn_engine",
        "angr.storage.memory_mixins.default_filler_mixin",
    ):
        logging.getLogger(name).setLevel(logging.ERROR)

    project = angr.Project(str(exe_path), auto_load_libs=False)

    cfg = project.analyses.CFGEmulated(
        starts=[FUNC_ADDR],
        keep_state=True,
        state_add_options=angr.options.refs,
        call_depth=0,
        normalize=True,
    )
    cdg = project.analyses.CDG(cfg, start=FUNC_ADDR)
    ddg = project.analyses.DDG(cfg, start=FUNC_ADDR)

    node = cfg.model.get_any_node(MODE_READ_ADDR)
    bs = project.analyses.BackwardSlice(
        cfg,
        cdg,
        ddg,
        targets=[(node, -1)],
        control_flow_slice=True,
    )

    mode_consts: list[int] = []
    cmp_blocks = []
    for addr in MODE_CMP_ADDRS:
        block = project.factory.block(addr)
        insns = []
        for insn in block.capstone.insns:
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            insns.append(f"0x{insn.address:08x}: {text}")
            imm = parse_imm_from_cmp(text)
            if imm is not None:
                mode_consts.append(imm)
        cmp_blocks.append(
            {
                "block_addr": f"0x{addr:08x}",
                "size": block.size,
                "insns": insns,
            }
        )

    mode_consts = sorted(set(mode_consts))

    mode = claripy.BVS("mode_id", 32)
    predicate = claripy.Or(*[mode == claripy.BVV(v, 32) for v in mode_consts]) if mode_consts else claripy.false
    sat_vals_0_31: list[int] = []
    solver = claripy.Solver()
    solver.add(predicate)
    for v in range(32):
        if solver.satisfiable(extra_constraints=[mode == v]):
            sat_vals_0_31.append(v)

    result = {
        "exe_path": str(exe_path),
        "function_addr": f"0x{FUNC_ADDR:08x}",
        "mode_read_addr": f"0x{MODE_READ_ADDR:08x}",
        "secondary_pass_block": f"0x{SECONDARY_PASS_BLOCK:08x}",
        "cfg_nodes": cfg.graph.number_of_nodes(),
        "cfg_edges": cfg.graph.number_of_edges(),
        "cdg_nodes": cdg.graph.number_of_nodes(),
        "cdg_edges": cdg.graph.number_of_edges(),
        "ddg_nodes": ddg.graph.number_of_nodes(),
        "ddg_edges": ddg.graph.number_of_edges(),
        "backward_slice_runs": [f"0x{x:08x}" for x in sorted(bs.runs_in_slice)],
        "compare_blocks": cmp_blocks,
        "mode_constants_extracted": mode_consts,
        "claripy_satisfying_values_0_31": sat_vals_0_31,
        "notes": [
            "BackwardSlice is function-scoped here (CFGEmulated starts=[RunTacticalAutoTurnControllerForActiveUnit]).",
            "Mode constants come from cmp-eax-immediate chain before secondary-pass dispatch block.",
            "Identifier analysis is intentionally not used (CGC-only according to angr warning on PE).",
        ],
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[saved] {out_json}")
    print(f"mode_constants_extracted={mode_consts}")
    print(f"claripy_satisfying_values_0_31={sat_vals_0_31}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
