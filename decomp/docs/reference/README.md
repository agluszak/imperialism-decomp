# Retail and source references

Use these for durable observed behavior, formats and ABI facts.
Current types/functions belong to C++ declarations, retail analysis
to the reviewed Ghidra database, and change history to Git.

## Files and resources

- [Save format](save_format.md) — `.imp` serialization and stream contracts.
- [Mac resources](macos-resource-oracle.md) — evidence and UI generation inputs.
- [Bitmap IDs](bitmap-ids.md) — observed UI/resource identifiers.
- [Cursor resource mapping](cursor-resource-mapping.md) and
  [cursor semantics](cursor-semantics-exe.md) — Windows resource IDs and uses.
- [String table](strenu-strings.tsv) — extracted UI text with IDs.
- [Manual](manual_text.txt) — extracted period gameplay manual.

## Gameplay and ownership evidence

- [Army stacks](army_stacks.md) and
  [tactical projection](army_tactical_projections.md).
- [Naval order ownership](navy_order_model.md) and
  [retail naval combat](navy_tactical_retail.md).
- [Turn-start events](turn_start_events.md).
- [Page pagination](page_view_pagination.md).
- [TGreatPower power-score family](tgreatpower-power-score-family.md).
- [stretch container](stretch-container.md).

These are evidence references, not recovery progress reports.
For current source rules see [decomp/AGENTS.md](../../AGENTS.md);
for executable Ghidra workflows see [docs/ghidra-db.md](../ghidra-db.md).
