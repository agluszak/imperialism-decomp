# Retail evidence references

Current reconstructed interfaces, layouts and algorithms belong in C++ source and
the reviewed Ghidra project. This directory holds information that is external
to the reconstructed source or established by independent retail observations.

- [Save format](save_format.md) — the `.imp` stream and serialization layout.
- [Mac UI resources](macos-resource-oracle.md) — resource evidence and UI generation.
- [Bitmap identifiers](bitmap-ids.md) — observed UI images and gameplay associations.
- [Cursor resources](cursor-resource-mapping.md) and
  [cursor semantics](cursor-semantics-exe.md) — retail cursor mappings.
- [Retail naval combat](navy_tactical_retail.md) — original-executable observation
  showing strategic resolution and the dormant tactical branch.
- [Extracted localization strings](strenu-strings.tsv) — UI strings with identifiers.
- [Extracted game manual](manual_text.txt) — original gameplay reference.

For the current code use `decomp/src/` and `decomp/include/`. For Ghidra operations
see [Ghidra database workflow](../ghidra-db.md). Earlier investigation and class
reconstruction notebooks remain available through Git history.
