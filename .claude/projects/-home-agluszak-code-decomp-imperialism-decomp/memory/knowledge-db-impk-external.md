---
name: knowledge-db-impk-external
description: class-discovery used to depend on an external impk CLI; now folded in-repo as impk_compat (2026-06-03)
metadata:
  type: project
---

RESOLVED 2026-06-03 (doc-consolidation pass). `just class-discovery`
(`tools/workflow/class_discovery.py`) previously shelled out via
`uv run --project <knowledge_root> impk ...` against the separate `imperialism_knowledge`
repo — confirmed dead 2026-06-01 (no real `impk` entrypoint; the old "impk" was a personal
shell alias; the knowledge repo's deps were also unresolvable / pre-migration pinned).

Fix: the self-contained compat shim was vendored into the repo as
`tools/workflow/impk_compat.py` (reads only this repo's `config/symbols.csv` +
`src/ghidra_autogen/index.csv` — no Ghidra DB, no sibling). `run_impk` now invokes
`python -m tools.workflow.impk_compat`, and `--knowledge-root` defaults to the repo root.
`just class-discovery` runs fully in-repo (verified: summary.json + candidates emitted).
See [[repo-layout-skills-and-vendor]].

**How to apply:** class-discovery is a compat-grade evidence ranker (static `g_vtbl*`
symbols + `::`-named autogen functions), not the old heavyweight live-Ghidra inference. For
deeper per-function evidence prefer `just slice-discovery`. See [[pyghidra-version-gate]].

Separately, on the original binary: `reccmp-user.yml` (gitignored, holds the ORIGINAL exe
path) does NOT currently exist — only `build-msvc500/reccmp-build.yml` (recompiled side) is
present. So the original must be (re)registered via `just bootstrap-reccmp`, which reads
`.env`'s `ORIGINAL_BINARY`. That was stale (`orig/Imperialism.exe`, dir absent); now set to
the real GOG path: /home/agluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Imperialism.exe.
reccmp-project.yml pins the expected sha256 6afab8495db715fd9e719cffa74abe5ede4dd763428ff65d73be4edf16c9e691.
