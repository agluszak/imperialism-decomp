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

`Startup.rsrc` `View` 1500 is a reproducibility sentinel: its ten decoded records must
match the Windows startup builder selected by event `0x5dc`, including the `base`,
`main`, `load`, `rand`, `mult`, `high`, `scen`, `curs`, `quit`, and `pref` tags and
their rectangles. Generation and checking fail if that correspondence changes.

## Resource ID scope

Classic Mac resource IDs are not globally unique across Imperialism's resource files.
The runtime searches the active Resource Manager chain, so an ID must be cited as
`resource file + type + ID`, for example `Startup.rsrc:View:1500`. Never merge records
solely because their numeric IDs match. `id_collisions.csv` makes these cross-file
collisions explicit.

## Generate the Windows UI factories

`config/ui_factory_codegen.yml` maps Windows factory addresses and event cases to
resource-file-scoped `View` IDs. `config/ui_factory_windows.json` describes the
Windows emission dialect and platform-specific overrides as structured data. Normal
generation consumes only those two configs and the committed `ui_views.json`; it never
reads either retail binary:

```sh
just ui-codegen-check
just ui-codegen
just ui-resource-show Startup.rsrc:1500
just build
just ui-codegen-match-gate
```

`just generate` writes one translation unit per factory under
`build-msvc500/generated/ui/`. Those generated claims participate in the central
source model, symbol projection, stub suppression, CMake, and diff-aware agent checks.
The former manually owned `src/game/turn_event_dialog_factory_*.cpp` files are therefore
absent; their 17 addresses have exactly one generated owner.

The manifest supports two direct resource emission shapes because the Windows binary
used both expanded member calls and compact builder helpers. Six mature factories use
the structured `resource_recipe` shape: Mac IR still owns their pane hierarchy, FourCCs,
rectangles, state, picture/string IDs, number ranges, and control values, while the
Windows recipe selects compact versus expanded calls, specialized Windows classes,
stack-pop shape, and genuine platform overrides. There are no C++ body templates and no
retail inputs in the normal generation path. The generated manifest hashes all three
committed inputs, and `just ui-codegen-match-gate` protects pairing and the accepted
similarity floor.
