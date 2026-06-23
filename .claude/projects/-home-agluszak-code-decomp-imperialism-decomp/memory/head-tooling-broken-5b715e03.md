---
name: head-tooling-broken-5b715e03
description: 5b715e03 regressed symbols.csv (broke just vtable + alignment) — FIXED in 22efcd3c; plus the docker build-flags gotcha
metadata:
  type: project
---

Commit 5b715e03 ("Regenerate ghidra_autogen folder") also regenerated `config/symbols.csv`
and regressed vtable-slot / scalar-deleting-destructor names. Symptoms:
- `just vtable`: 272/272 "not matching" — every class failed at slot 0x04 because the scalar
  deleting destructor got renamed away from `<Class>::`scalar deleting destructor'` (the form the
  recomp `??_G` PDB symbol uses) to `'scalar_deleting_destructor'` / `Destruct<Class>AndMaybeFree`,
  plus order/command class slot renames.
- `just stats`: aligned 685 -> 316 (-369) vs baseline.

**FIXED in commit 22efcd3c** by restoring `config/symbols.csv` to its 90ae4d8a state (90ae4d8a is
the direct parent of 5b715e03, so this reverts only that regression). Result: `just vtable` 327
found / 0 not matching (100%); `just stats` 685 aligned (+0). If a future symbols regen re-breaks
this, re-check the scalar-dtor name form first. Also refreshed `config/vtable_gate_baseline.csv` for
the autogen raw-vtable drift (TDiplomacyMgr/TTechMgr).

Separate build gotcha (still relevant): when hand-running the docker build (e.g. to bypass a gate),
use the justfile's exact `cmake_flags`:
`-DCMAKE_BUILD_TYPE=RelWithDebInfo -DIMPERIALISM_LINK_MFC=ON -DIMPERIALISM_MATCH_FLAGS_CSV=/Oy-,/Ob1`.
Building with `-DCMAKE_BUILD_TYPE=Release` yields a ~120 KB exe and NO fresh PDB, leaving a stale
PDB that makes reccmp crash with `InvalidVirtualAddressError`. A correct build = ~742 KB exe + fresh
4.8 MB pdb. Also: `just detect` must repopulate `build-msvc500/reccmp-build.yml` after a `rm -rf` of
the build dir, or reccmp-vtable reports "missing recompiled_path". Don't run `just regen-stubs`
unless you actually added/removed `// FUNCTION` markers (it downgrades typed stub sigs). See
[[stub-regen-thunks-alias-collision]].
