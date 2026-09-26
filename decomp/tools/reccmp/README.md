# reccmp helpers

The pinned reccmp fork is the comparison engine. This directory contains only the small
Imperialism-specific glue needed for batch comparison, structured triage, CRT startup evidence, and
address translation.

Use project commands rather than treating a generated progress report as a second source of truth:

```sh
just build
just triage 0xADDR
just compare 0xADDR       # optional raw diff
just vtable ClassName
just datacmp
```

`just build` refreshes the native Clang source index required by the pinned reccmp. To refresh only
that index after editing source, run `just source-index`; comparison still uses the existing VC5
executable and PDB. Rebuild the [MSVC Docker image](../../docker/msvc500/README.md) if it predates the
LLVM 19 development-library dependencies.

The batch, triage, and address helpers load complete symbol pairing before selecting functions for
comparison. This preserves callee identities even when their bodies are outside the requested batch.

`exact` and `effective` are completed comparison results. Only `mismatch` is source-recovery evidence;
`inconclusive` means inspect pairing, metadata, or retail evidence. There is no committed score ledger or
baseline to update.
