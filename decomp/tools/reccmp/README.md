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

`exact` and `effective` are completed comparison results. Only `mismatch` is source-recovery evidence;
`inconclusive` means inspect pairing, metadata, or retail evidence. There is no committed score ledger or
baseline to update.
