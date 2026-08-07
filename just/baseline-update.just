# baseline-update — targets that REWRITE committed baselines/configs.
#
# Imported by the root justfile. just's `import` shares one scope, so these
# recipes use the root's settings and constants ({{target}}, {{build_dir}}, ...)
# and appear in `just --list` under their [group('baseline-update')] exactly as
# if they were still inline.

# MUTATES: the aggregate JSON and per-function CSV reccmp progress baselines.
# The snapshot's `stub_count` is a ratchet, not an observation: it falls freely but a
# rise is held back (gate stays red) unless ALLOW_POLICY_BASELINE_UPDATE=1.
[group('baseline-update')]
stats-baseline-update *args:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled --commit-baseline {{args}}

[doc('MUTATES: config/tooling_surface.csv. Appends placeholder rows for justfile modules missing from the manifest (fill in each note); never removes stale rows')]
[group('baseline-update')]
tooling-surface-update:
  uv run python -m tools.workflow.check_tooling_surface --write

# MUTATES: the stub_count field of config/baselines/reccmp_progress_baseline.json.
[group('baseline-update')]
stub-count-gate-update:
  uv run python -m tools.workflow.baseline_guard --wrap "config/baselines/reccmp_progress_baseline.json" -- uv run python -m tools.workflow.check_stub_count --write-baseline

# MUTATES: config/baselines/datacmp_baseline.csv.
[group('baseline-update')]
datacmp-gate-update:
  uv run python -m tools.workflow.baseline_guard --wrap "config/baselines/datacmp_baseline.csv" -- uv run python -m tools.workflow.check_datacmp_baseline --target "{{target}}" --build-dir "{{build_dir}}" --write-baseline

# MUTATES: config/baselines/ctor_placement_baseline.txt (architecture-rule exception).
[group('baseline-update')]
ctor-placement-gate-update:
  uv run python -m tools.workflow.baseline_guard --wrap "config/baselines/ctor_placement_baseline.txt" -- uv run python -m tools.workflow.check_ctor_placement --write-baseline

# MUTATES: config/baselines/empty_body_baseline.csv.
[group('baseline-update')]
noop-gate-update:
  uv run python -m tools.workflow.baseline_guard --wrap "config/baselines/empty_body_baseline.csv" -- uv run python -m tools.workflow.check_empty_bodies --write-baseline config/baselines/empty_body_baseline.csv

# MUTATES: config/baselines/semantic_call_contract_baseline.json. Pure debt
# shrink is accepted; initialization, denominator growth, or mode changes need
# the standard explicit policy approval.
[group('baseline-update')]
semantic-gate-update:
  uv run python -m tools.workflow.baseline_guard --wrap "config/baselines/semantic_call_contract_baseline.json" -- uv run python -m tools.semantic_calls --target "{{target}}" --build-dir "{{build_dir}}" update-baseline

# MUTATES: reccmp-project.yml ignore lists (Hard Rule 14).
[group('baseline-update')]
generate-ignores:
  uv run python -m tools.reccmp.generate_ignore_functions --target "{{target}}" --apply
