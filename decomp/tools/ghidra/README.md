# Ghidra tools

The vendored project and `ghidra.toml` are the source of truth for Ghidra version, release, and
program name. Run the project commands from `decomp/`.

## Normal inspection

Use the `just ghidra` dispatcher for listing-first investigation:

```sh
just ghidra-daemon
just ghidra listing 0xADDR
just ghidra xrefs to 0xADDR
just ghidra string-oracle 0xADDR
just ghidra decompile 0xADDR
```

The daemon keeps one read-only project open and makes repeated queries fast. A mutation or one-shot
tool evicts it; start it again when needed. Treat names, decompilation, and calling conventions as
provisional until instructions, data, registers, and stack cleanup support them.

## Deliberate changes

Use the matching `just` mutation target for a confirmed database change. Inspect the result and export
the project explicitly:

```sh
just ghidra-apply-source --apply
just export-project
```

`refresh-inventory` is for an intentional Ghidra boundary repair. It refreshes the curated inventory
from the database; it never writes C++ source. Source markers and declarations remain the one-way,
hand-authored source model. Generated evidence belongs under the build directory and is disposable.
