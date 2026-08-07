# Mac-to-Windows string crosswalk

The committed crosswalk joins the file-scoped Mac `STR#` corpus with Windows
`STR#ENU.GOB` strings, named embedded string globals, source-owned function
references, and generated UI-factory resource references.

```sh
just mac-string-search "railroad"
just string-crosswalk 10045 6
just string-crosswalk 1509 2
just strings-for-function 0x0056f560
just strings-for-function 0x0043dbc0
```

The index is generated deterministically at
`docs/reference/mac_string_crosswalk.json`. Refresh it with
`just mac-string-crosswalk-update`; normal source gates run
`just mac-string-crosswalk-check` and never require either retail binary or the
game runtime.

## Evidence levels

For global localized strings in `Strings.rsrc`, the strongest join is the
Windows resource lookup formula:

```text
LoadStringA ID = (Mac STR# group * 100 + Mac string index) & 0xffff
```

The existing Windows TSV records STRINGTABLE resource names as blocks. Its
historical `id` column is one block (16 IDs) above the actual `LoadStringA` ID,
so both `legacy_tsv_id` and the corrected `load_string_id` are retained.

Local strings embedded in View resource files do not use that formula. They are
matched by exact text, normalized newlines/case/punctuation, and compatible
placeholder structure against the Windows GOB and named globals. Every candidate
keeps its reason and score; ties are explicitly marked ambiguous.

`strings-for-function` is source-only. It recognizes constant group/index calls,
named embedded globals, and the Mac resources consumed by generated factories.
Dynamic group or index expressions remain unresolved rather than being guessed.

Mac `TEXT` resources are not yet present in the committed decoded evidence. Their
decode and subsequent inclusion in this same index are tracked by Bead
`imperialism-decomp-1uj.77.4`.
