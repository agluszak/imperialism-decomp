---
name: knowledge-db-impk-external
description: class-discovery depends on an external impk CLI + separate imperialism_knowledge repo that isn't installed
metadata:
  type: project
---

`just class-discovery` (`tools/workflow/class_discovery.py`) shells out via
`uv run --project <knowledge_root> impk ...` against the SEPARATE repo `imperialism_knowledge`
at /home/agluszak/code/decomp/imperialism_knowledge. Confirmed dead 2026-06-01, three
independent reasons:
1. There is NO `impk` entrypoint — not in that repo's `pyproject.toml` `[project.scripts]`,
   not in `scripts/`, not in `.venv/bin`. The user recalls `impk` was just a personal shell
   ALIAS for the knowledge repo on the old machine — but class_discovery calls it via
   subprocess (no shell), so a shell alias never resolved through that code path anyway.
2. The knowledge repo's own deps don't resolve: it pins `pyghidra==3.0.2` (needs
   `jpype1==1.5.2`) against `jpype1==1.6.0` — uv reports unsatisfiable.
3. It's still pinned to PRE-migration versions (`pyghidra==3.0.2`, `ghidra-stubs==12.0.2`),
   not the 12.1 / 3.1.0 this repo moved to.

**Why:** This is the heavyweight class/vtable inference subsystem ("the knowledge DB"). It is
distinct from the in-repo export pipeline (`symbols.csv` + `src/ghidra_autogen/`), which is the
live source of truth and works without impk. control_plane.md strategy items #8/#9 still assume
this tool is available.

**How to apply:** Reviving class-discovery is real work, not a path fix: define an actual
`impk` console-script in imperialism_knowledge, repair its dep pins, and migrate it to
12.1/3.1.0. Until then treat class-discovery as deprecated and rely on the in-repo
`symbols.csv` + `src/ghidra_autogen/` pipeline, which is self-contained and works.
See [[pyghidra-version-gate]].

Separately, on the original binary: `reccmp-user.yml` (gitignored, holds the ORIGINAL exe
path) does NOT currently exist — only `build-msvc500/reccmp-build.yml` (recompiled side) is
present. So the original must be (re)registered via `just bootstrap-reccmp`, which reads
`.env`'s `ORIGINAL_BINARY`. That was stale (`orig/Imperialism.exe`, dir absent); now set to
the real GOG path: /home/agluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Imperialism.exe.
reccmp-project.yml pins the expected sha256 6afab8495db715fd9e719cffa74abe5ede4dd763428ff65d73be4edf16c9e691.
