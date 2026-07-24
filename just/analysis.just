# ---------------------------------------------------------------------------
# analysis — boundary/collection/template audits (read-only reports).
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

[doc('Assign src/game files to subsystems via the original module map')]
[group('analysis')]
assign-subsystems *args:
  uv run python -m tools.analysis.assign_subsystems {{args}}

# Manual/autogen boundary report: every autogen stub referenced from manual
# sources, with call/address-take split, caller counts, original size, and
# (when Ghidra is available) cc/params/RET-imm facts + a porting classification.
[doc('Report every manual-source reference to an autogen stub, classified for porting')]
[group('analysis')]
boundary-audit *args:
  uv run python -m tools.workflow.boundary_audit {{args}}

# Embedded-MFC-collection audit for an owner ctor (0xADDR or class name): member
# offset, vtable family/slot-0 identity, block size, ctor/dtor copy census, and a
# normalized-body twin scan for per-TU duplicate template COMDATs. See the
# mfc-collections skill's three-problem taxonomy (rules MFC-EMBED-029/MFC-TWIN-030).
[doc('Audit an embedded MFC collection member: identity, offsets, duplicate-COMDAT twins')]
[group('analysis')]
mfc-collection-audit *args:
  uv run python -m tools.workflow.mfc_collection_audit {{args}}

# Template-emission compiler matrix (docs/toolchain.md): compile the probe TUs in
# the msvc500 container per cell (/Ob levels, TU splits, wrapper/init/dtor axes)
# and inventory the CList COMDATs each TU emits (host-side COFF parse).
[doc('Run the template-emission matrix and report per-TU CList COMDAT inventories')]
[group('analysis')]
template-emission-matrix *args:
  uv run python -m tools.workflow.template_emission_matrix {{args}}

# Re-verify every row of config/template_aliases.csv per equivalence class:
# duplicate_emission rows must be identical modulo relocations
# (tools.binary.body_hash); folded_symbol_group rows must be bare jmp islands
# whose fold chain lands on the recorded canonical.
[doc('Validate equivalence-metadata rows in config/template_aliases.csv')]
[group('analysis')]
template-alias-check:
  uv run python -m tools.workflow.template_alias_check

# Refresh the CString field snapshot from the semantic model + real VC5 layout
# oracle, then regenerate the reviewed clone/raw-span report.
[doc('Refresh the VC5-backed CString ownership and raw-span audit')]
[group('analysis')]
cstring-ownership-audit:
  just generate-type-model
  uv run python -m tools.workflow.cstring_ownership_audit --write

# Enumerate incremental-link stale-jmp fold islands (folded_symbol_group
# candidates for config/template_aliases.csv); --emit prints ready CSV rows.
[doc('Enumerate stale-jmp fold islands for folded_symbol_group rows')]
[group('analysis')]
stale-jmp-islands *args:
  uv run python -m tools.workflow.stale_jmp_islands {{args}}
