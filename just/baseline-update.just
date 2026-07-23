# baseline-update — targets that REWRITE committed baselines/configs.
#
# Imported by the root justfile. just's `import` shares one scope, so these
# recipes use the root's settings and constants ({{target}}, {{build_dir}}, ...)
# and appear in `just --list` under their [group('baseline-update')] exactly as
# if they were still inline.

# MUTATES: the aggregate JSON and per-function CSV reccmp progress baselines.
[group('baseline-update')]
stats-baseline-update:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled --commit-baseline

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

# MUTATES: config/baselines/empty_body_baseline.csv.
[group('baseline-update')]
noop-gate-update:
  uv run python -m tools.workflow.baseline_guard --wrap "config/baselines/empty_body_baseline.csv" -- uv run python -m tools.workflow.check_empty_bodies --write-baseline config/baselines/empty_body_baseline.csv

# MUTATES: reccmp-project.yml ignore lists (Hard Rule 14).
[group('baseline-update')]
generate-ignores:
  uv run python -m tools.reccmp.generate_ignore_functions --target "{{target}}" --apply
