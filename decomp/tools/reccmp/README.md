# reccmp integration

The pinned fork owns entity pairing and comparison preparation. Ghidriff owns decompiled-code
differencing. Imperialism composes these through authored selectors and saved reports:

```sh
just build
just compare --all --output build/comparisons/BASELINE
just compare --changed
just compare --file src/game/map_generation/TMapMaker.cpp
just compare-report build/comparisons/HEAD --base build/comparisons/BASE
just compare-report build/comparisons/BASELINE --queue --output build/campaign.json
just addr 0xADDR
just vtable ClassName
just datacmp
```

Comparison selects authored `FUNCTION` markers through `tools.source_model`. Compiler, template,
library, stub, and generated factory claims retain their pairing identities without joining the
authored dataset. No function ignore list or effective-score layer duplicates that classification.

The four outcomes are `no-differences`, `differences`, `unpaired`, and `analysis-failed`. Differences
do not produce a failed percentage gate. Saved artifacts preserve code/data findings, inline retry
results, direct calls, analysis failures, and input identities. Dataset deltas report shared-function
transitions and added/removed claims separately; they do not infer the cause of a transition.

`just build` refreshes the native source index. `just source-index` refreshes only that projection;
comparison consumes the existing VC5 executable/PDB. Rebuild the [Docker image](../../docker/msvc500/README.md)
if it predates LLVM 21. The source-index cache is `build-msvc500/reccmp-source/`; comparison analysis
is disposable under `build/reccmp-ghidra/`. The committed Ghidra archive remains the reviewed
evidence database, and comparison only reads its restored signatures.
