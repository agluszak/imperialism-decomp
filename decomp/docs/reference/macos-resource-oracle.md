# Mac UI resource oracle

The retail Mac build describes its UI in custom `View` resources. It does not use
PowerPlant `PPob`/`PPTM` resources. The normalized evidence inventory is vendored under
`vendor/macos_codewarrior/evidence/resources/`; no retail image or raw bitmap/audio
payload is committed. Small text-style payloads are retained as hex beside their named
fields, and `TEXT` is retained as decoded MacRoman text so the evidence is directly
searchable.

Like the CodeWarrior symbol inventory, this is an oracle rather than Windows ABI
evidence. It can establish source-era pane/control tags, class names, resource names,
layout rectangles, and likely relationships between screens. It cannot assign Windows
addresses, calling conventions, vtable slots, or inheritance.

`ghidra portprep` builds its control-usage hints directly from this evidence and the
current Windows source. It joins directly referenced original `U*.cpp` path strings to
qualified Windows class owners, then carries those module candidates through matching
Mac View classes. Direct function/class links are confirmed; Mac screen and generated
factory joins remain candidate evidence.

## Reproduce it

Install `hfsutils` so `hmount`, `hcopy`, and `humount` are available. Then either set
`MACOS_IMPERIALISM_DUMP` in `.env` and regenerate all Mac evidence:

```sh
just mac-evidence
just mac-evidence-check
```

or regenerate only the resource inventory from an explicit source:

```sh
just mac-resource-evidence /path/to/Imperialism
just mac-resource-evidence-check
```

The source may be the retail directory containing `IMPERIALISM01.iso`, that HFS ISO
itself, or a directory of resource files previously copied in MacBinary mode and named
`*.rsrc.bin`. Extraction uses a temporary directory. Generation writes only these
deterministically sorted files:

| File | Contents |
| --- | --- |
| `summary.json` | Counts, a source-set fingerprint, resource-file inventory, and the Windows cross-check result |
| `views.csv` | `View` ID/name, serialized size/hash, and widget count |
| `widgets.csv` | Screen, record offset, nesting, four-character type/tag, class, and rectangle |
| `ui_views.json` | Typed generator IR: hierarchy (including embedded `nmbr` controls), FourCC integers, geometry, state/command values, and typed picture, text/style/alignment, number, cluster, edit, text-view, and window properties |
| `pictures.csv` | `PICT` ID/name, bounds, serialized size/hash; no pixels |
| `strings.csv` | `STR#` group ID/name and one-based index/text |
| `text_styles.csv` | Flat `TxSt` index with font name, point size, QuickDraw face flags, RGB color, raw bytes, confidence, and the explicitly unexplained alignment byte |
| `text_resources.json` | Canonical decoded `TxSt`, MacRoman `TEXT`, and TextEdit `styl` runs, including run ranges, font/face/size/color, line height/ascent/leading, raw style bytes, and confidence |
| `id_collisions.csv` | Same type/ID appearing in multiple resource files |

The checker validates every decoded hierarchy for one reachable root, ordered and
non-overlapping siblings, parent containment, family FourCC identity, and typed-family
minimum lengths. Fresh extraction also rejects missing or ambiguous family markers and
records per-node decoder confidence while preserving unparsed bytes as hex evidence.
`TxSt` must be a ten-byte `TextStyle` header plus an exactly bounded Pascal font name.
`styl` must be a TextEdit `StScrpRec`: one run count followed by fixed 20-byte
`ScrpSTElement` records whose starts are ordered and bounded by the paired `TEXT`.
This layout is also documented by Apple's archived
[Text Media Handlers guide](https://developer.apple.com/library/archive/documentation/QuickTime/RM/MediaTypesAndHandlers/MHFundamentals/D-Chapter/4TextMediaHandlers.html).

Real-resource sentinels pin both the resource SHA and selected decoded properties for
`MapView.rsrc` 1350/2013, `Linger.rsrc` 2020, `Multiplayer.rsrc` 1507,
`Startup.rsrc` 1500, and `Univ.rsrc` 9210. Together they cover nested clusters,
window/float-window records, static/deluxe/edit/text-view styles, number controls,
nonzero picture/control insets, and the deeply nested university hierarchy. Separate
style sentinels pin bold and nonblack `TxSt` records plus a three-run `TEXT`/`styl`
pair. `Startup.rsrc` 1500 additionally retains its ten-record Windows event `0x5dc`
correspondence check.

## Resource ID scope

Classic Mac resource IDs are not globally unique across Imperialism's resource files.
The runtime searches the active Resource Manager chain, so an ID must be cited as
`resource file + type + ID`, for example `Startup.rsrc:View:1500`. Never merge records
solely because their numeric IDs match. `id_collisions.csv` makes these cross-file
collisions explicit.

## Generate the Windows UI factories

`config/ui_factory_codegen.yml` maps Windows factory addresses and event cases to
resource-file-scoped `View` IDs. A genuinely Windows-only screen is represented as a
semantic tree in `config/ui_factory_windows_views.yml`; that file records widget classes,
hierarchy, geometry, state, typed family properties, and binary evidence, but never
allocation shape, helper selection, variable names, or explicit stack pops. Normal
generation consumes committed evidence only and never reads either retail binary:

```sh
just ui-codegen-check
just ui-codegen
uv run python -m tools.ui_cpp_codegen --view Startup.rsrc:1500
uv run python -m tools.ui_cpp_codegen --gen-dir build-msvc500/generated/ui --explain 0x43dbc0 0x07dd tool
uv run python -m tools.ui_cpp_codegen --gen-dir build-msvc500/generated/ui --triage-map 0x43dbc0
just build
```

`just generate` writes one translation unit per factory under
`build-msvc500/generated/ui/`. Those generated claims participate in the central
source model, symbol projection, stub suppression, and CMake.
The former manually owned `src/game/turn_event_dialog_factory_*.cpp` files are therefore
absent; their 17 addresses have exactly one generated owner.

All 17 factories use the same canonical semantic emitter. Mac `View` IR supplies class,
hierarchy, geometry, state, control values, strings, and typed family payloads. The
generator derives VC5 source shape, helper calls, stable variable names, and hierarchy
closure. There are no compact/expanded modes, per-node operation arrays, manual pop
lists, class maps, string-symbol maps, or `config/ui_factory_windows.json`.

Event `0x05e7` is represented by the small evidenced Windows-only tree because no Mac
`View` counterpart exists. The Windows file is validated to reject code-generation
choreography; any future Windows-only case must provide a rooted semantic tree and an
evidence range. Every declared case must emit exactly one rooted tree or carry an
explicit rejection plus evidence.

Generation writes `_source_map.json` beside the TUs. It maps every event/node to its
tag, class, semantic evidence, confidence, and generated line span. The explain command
selects a node by record offset or tag; the triage command summarizes case coverage and
confidence before machine-level `just triage` work. There are no C++ body templates or
retail inputs in the normal generation path. The generated manifest hashes every
committed semantic input. Platform deltas are declared directly in
`config/ui_platform_deltas.yml` and checked by the runtime UI oracle when it needs them.
Mac-backed nodes use Mac semantics; Windows-only nodes carry their listing evidence in
the semantic catalog. No generated crosswalk or report is a source of truth.
