# Ghidra database workflow

The vendored project under `vendor/ghidra/` is authoritative. Git history already
preserves how it got here; do not rebuild it from obsolete replay tools.

## Inspect

```sh
just ghidra-daemon          # optional warm JVM for fast queries
just ghidra listing 0xADDR
just ghidra decompile 0xADDR
just ghidra xrefs 0xADDR
just ghidra search ...
just ghidra portprep 0xADDR
just ghidra vtable-dump Class=0xVT
```

`just ghidra` with no subcommand lists the full dispatcher.

## Mutate

Deliberate DB repairs stay dry-run by default and require `--apply`:

- repair missing functions
- fix function bounds
- define switch tables
- demote fake functions
- delete bad labels

Invoke the matching private `just` recipe (or the underlying
`tools.ghidra.*` module) from the Ghidra skill when a repair is needed. Always
inspect the result before exporting.

## Sync source names into Ghidra

```sh
just ghidra-apply-source           # dry-run
just ghidra-apply-source --apply   # write names / namespaces / vtable labels
```

This is the one sanctioned source→Ghidra operation. It applies confirmed source
markers and straightforward signatures; it does not regenerate layouts or replay
historical type-projection campaigns.

## Restore and export

```sh
just restore-project   # fresh checkout / recreate the live project from the .gzf
just export-project    # refresh vendor/ghidra/exports/*.gzf after a DB change
```

Export before committing any Ghidra-side change so the LFS archive matches the
live project. After inventory boundary work, `just refresh-inventory` then
`just export-project`.
