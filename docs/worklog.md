# Worklog

## 2026-02-22

### Infrastructure and pipeline
1. Fixed rootless Docker runtime path for this host:
   1. `storage-driver=fuse-overlayfs`
   2. `features.containerd-snapshotter=false`
2. Standardized Docker invocation for this project:
   1. `docker build --network host ...`
   2. `docker run --network none ...`
3. Confirmed containerized MSVC build works end-to-end on current machine.

### Build-system and autogen changes
1. Replaced single-file stub generation with chunked stubs:
   1. `tools/stubgen.py` now writes `src/autogen/stubs/stubs_part*.cpp`.
   2. Writes `src/autogen/stubs/_manifest.json`.
2. Updated `CMakeLists.txt` to compile all `src/autogen/stubs/*.cpp`.
3. Removed legacy dependency on `src/autogen/stubs.cpp`.
4. Added temporary local placeholders in `src/game/thunks.cpp` for two unresolved callee symbols.

### Ghidra resync
1. Ran clean full sync from Ghidra 12.0.2 project:
   1. `12230` user-defined functions exported.
   2. `4935` globals exported.
   3. `455` decompiled body files.
   4. `17` type header files (`595` types).

### Similarity and scope control
1. Added `tools/reccmp/symbol_buckets.py` (shared bucket classifier).
2. Added `tools/reccmp/library_inventory.py` (bucket + similarity summary).
3. Added `tools/reccmp/generate_ignore_functions.py`:
   1. Generates candidate ignore lists from symbol buckets.
   2. Writes patch block and JSON artifacts.
   3. Can apply directly to `reccmp-project.yml`.
4. Applied ignore set to `reccmp-project.yml`:
   1. `report.ignore_functions`: `2606` names.
   2. Buckets: `crt_likely`, `mfc_likely`, `directx_audio_net_likely`.

### Baseline numbers recorded
1. Full compare:
   1. `12229` paired / `12229` original.
   2. `42` aligned.
   3. `1.13%` average similarity.
2. Focused compare (with ignores):
   1. `10311` functions compared.
   2. `42` aligned.
   3. `1.32%` average similarity.

### Next actions
1. Split “focused” and “full” metrics in reporting to avoid confusion.
2. Lock ignore-generation policy (which buckets are permanent vs temporary).
3. Start targeted implementation batches from high-impact game functions.
