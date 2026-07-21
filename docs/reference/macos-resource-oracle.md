# Mac UI resource oracle

The retail Mac build describes its UI in custom `View` resources. It does not use
PowerPlant `PPob`/`PPTM` resources. The normalized, metadata-only inventory is vendored
under `vendor/macos_codewarrior/evidence/resources/`; no retail image or raw bitmap,
audio, or serialized resource payload is committed.

Like the CodeWarrior symbol inventory, this is an oracle rather than Windows ABI
evidence. It can establish source-era pane/control tags, class names, resource names,
layout rectangles, and likely relationships between screens. It cannot assign Windows
addresses, calling conventions, vtable slots, or inheritance.

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
| `ui_views.json` | Typed generator IR: hierarchy (including embedded `nmbr` controls), FourCC integers, geometry, state/command values, and typed picture, text, number, cluster, edit, text-view, and window properties |
| `pictures.csv` | `PICT` ID/name, bounds, serialized size/hash; no pixels |
| `strings.csv` | `STR#` group ID/name and one-based index/text |
| `text_styles.csv` | `TxSt` ID/name and serialized size/hash; no payload |
| `id_collisions.csv` | Same type/ID appearing in multiple resource files |

The checker validates every decoded hierarchy for one reachable root, ordered and
non-overlapping siblings, parent containment, family FourCC identity, and typed-family
minimum lengths. Fresh extraction also rejects missing or ambiguous family markers and
records per-node decoder confidence while preserving unparsed bytes as hex evidence.

Real-resource sentinels pin both the resource SHA and selected decoded properties for
`MapView.rsrc` 1350/2013, `Multiplayer.rsrc` 1507, `Startup.rsrc` 1500, and
`Univ.rsrc` 9210. Together they cover nested clusters, window/float-window records,
static text, edit and number controls, text views, nonzero picture/control insets, and
the deeply nested university hierarchy. `Startup.rsrc` 1500 additionally retains its
ten-record Windows event `0x5dc` correspondence check.

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
just ui-resource-show Startup.rsrc:1500
just ui-codegen-explain 0x43dbc0 0x07dd tool
just ui-codegen-triage 0x43dbc0
just ui-platform-diff --function 0x43dbc0 --event 0x07dd
just build
just ui-codegen-match-gate
```

`just generate` writes one translation unit per factory under
`build-msvc500/generated/ui/`. Those generated claims participate in the central
source model, symbol projection, stub suppression, CMake, and diff-aware agent checks.
The former manually owned `src/game/turn_event_dialog_factory_*.cpp` files are therefore
absent; their 17 addresses have exactly one generated owner.

All 17 factories use the same canonical semantic emitter. Mac `View` IR supplies class,
hierarchy, geometry, state, control values, strings, and typed family payloads. The
generator derives VC5 source shape, helper calls, stable variable names, and hierarchy
closure. There are no compact/expanded modes, per-node operation arrays, manual pop
lists, class maps, string-symbol maps, or `config/ui_factory_windows.json`.

Event `0x05e7` is represented by the small evidenced Windows-only tree because no Mac
`View` counterpart exists. The Windows file is schema-checked to reject code-generation
choreography; any future Windows-only case must provide a rooted semantic tree and an
evidence range. Every declared case must emit exactly one rooted tree or carry an
explicit rejection plus evidence.

Generation writes `_source_map.json` beside the TUs. It maps every event/node to its
tag, class, semantic evidence, confidence, and generated line span. The explain command
selects a node by record offset or tag; the triage command summarizes case coverage and
confidence before machine-level `just triage` work. There are no C++ body templates or
retail inputs in the normal generation path. The generated manifest hashes every
committed semantic input, and `just ui-codegen-match-gate` protects symbol pairing and
the explicitly accepted similarity baseline rather than dictating source architecture.

`docs/reference/ui_platform_diff.json` joins those generated line spans back to the
normalized Mac nodes and declared Windows deltas. The corresponding source gate rejects
unexplained class substitutions, undeclared functional-parity cases, missing generated
nodes, and stale reports. Ordinary Mac-backed nodes are explicitly reported as using
Mac semantics without pretending that per-node Windows-binary recipes still exist;
Windows-only nodes retain their listing evidence. `ui-codegen-triage` includes the case
classification and intentional-delta counts in its summary.
