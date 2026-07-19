# reccmp Library Symbol Matching

This note records the investigation of why calls to MSVC/MFC library functions can
compare as different names after the MSVC500 FID import. The concrete example was:

```text
orig call target:   ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
recomp call target: CPtrList::AddHead(void *)
```

These are the same logical MSVC C++ symbol. The decorated name demangles to
`public: struct __POSITION * __thiscall CPtrList::AddHead(void *)`.

## What reccmp Supports

`reccmp` does support MSVC demangling, but not as a general fallback for matching an
original-side `name` against a recompiled-side `symbol`.

Relevant paths in `/home/agluszak/code/decomp/reccmp`:

```text
reccmp/cvdump/demangler.py
  - wraps pydemumble as msvc_demangle()
  - helper get_function_arg_string() is used for overload disambiguation

reccmp/cvdump/analysis.py
  - PDB/PUBLICS decorated name becomes CvdumpNode.decorated_name
  - PDB/SYMBOLS friendly name becomes CvdumpNode.friendly_name
  - node.name() prefers friendly_name over decorated_name

reccmp/compare/ingest.py
  - load_markers() loads source annotations
  - load_data_sources() loads CSV files after source annotations
  - CSV metadata overwrites same-address annotation metadata

reccmp/compare/match_msvc.py
  - match_symbols(): exact orig symbol == recomp symbol
  - match_functions(): exact orig name == recomp name
  - no mixed decorated-name-to-demangled-name fallback

reccmp/compare/mutate.py
  - unique_names_for_overloaded_functions() runs after matching
  - it appends demangled argument strings only for already-known duplicate names

reccmp/compare/db.py
  - matched entity metadata is orig_data | recomp_data
  - recomp name/symbol wins after a successful match
```

The `symbol` and `name` fields are separate in reccmp:

```text
symbol = linker/decorated name, e.g. ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
name   = friendly compare name, e.g. CPtrList::AddHead
```

This is also documented in upstream `docs/csv.md`: CSV supports both `name` and
`symbol` columns, and CSV rows overwrite source annotations for the same address.

## Marker Behavior

For explicit by-name markers (`LIBRARY`, `SYNTHETIC`, `TEMPLATE`), reccmp reads the
following comment line as the identity:

```c++
// LIBRARY: TARGET 0x12345678
// SomeNameOrSymbol
```

Parser behavior:

```text
if the comment starts with "?"
  -> stored as symbol
else if marker has "SYMBOL" option
  -> stored as symbol
else
  -> stored as name
```

So this source annotation is enough for decorated MSVC C++ names:

```c++
// LIBRARY: TARGET 0x12345678
// ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
```

and this form is required for non-`?` linker names that should be treated as symbols:

```c++
// LIBRARY: TARGET 0x12345678 SYMBOL
// __strlwr
```

## What ISLE Does

ISLE mostly relies on source annotations rather than a bulk `symbols.csv` for library
identity. Examples from `/home/agluszak/code/decomp/isle`:

```text
ISLE/library_msvc.h
LEGO1/library_msvc.h
LEGO1/library_smartheap.h
LEGO1/library_smack.h
```

The headers contain disabled C/C++ blocks with `// LIBRARY` markers followed by the
library identity comment. The C++ decorated library identities often start with `?`,
so reccmp's parser stores them as `symbol`, not as `name`.

That is the key difference from our current generated CSV route. ISLE's decorated
library comments go through the marker parser's symbol path; our imported FID rows
currently go through the CSV `name` path unless we add/use a `symbol` column.

## What Happened in Imperialism

For `CPtrList::AddHead`:

```text
original binary:
  0x0060201d
  decorated identity: ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
  body size: 0x2a

recompiled binary:
  0x00472736
  PDB friendly name: CPtrList::AddHead
  PDB decorated symbol: ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
  body size: 0x2a
```

The wrapper `0x004885d0` calls the original body directly:

```text
0x004885d8 CALL 0x0060201d
```

The ILT thunk found nearby is unrelated to this specific call target:

```text
0x00401140 JMP 0x004885d0
```

The problem is therefore not ILT resolution. The problem is that our generated
`config/symbols.csv` row currently has the decorated identity in `name`:

```text
60201d|?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z|42|function|...
```

Because `config/symbols.csv` is listed as a reccmp data source, that CSV row loads
after the source marker and overwrites same-address marker metadata. The source marker
comment in `src/game/CPtrList.cpp` says `CPtrList::AddHead`, but the CSV row replaces
the name with the decorated string and does not provide a separate `symbol`.

Result:

```text
orig entity:
  name   = ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
  symbol = missing

recomp entity:
  name   = CPtrList::AddHead
  symbol = ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
```

`match_symbols()` cannot match because the original entity has no `symbol`.
`match_functions()` cannot match because the original `name` is decorated while the
recompiled `name` is friendly.

After the library body remains unmatched, call-target replacement in wrapper compares
the two unresolved names:

```text
-call ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z (FUNCTION)
+call CPtrList::AddHead(void *) (FUNCTION)
```

## Correct Representation

FID-derived library rows should preserve both identities:

```text
address|name|symbol|size|type|prototype
60201d|CPtrList::AddHead|?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z|42|function|...
```

For rows where we only know a decorated MSVC C++ name, generate a friendly `name` by
demangling and normalizing it enough to match reccmp/PDB friendly names, while keeping
the exact decorated string in `symbol`.

For rows where the linker name is a C/CRT symbol such as `_malloc` or `_strcmp`, keep
the linker identity in `symbol` when it must match by symbol. A friendly `name` can be
the same string if no better display name exists.

## Recommended Fix

1. Extend `config/symbols.csv` to include a `symbol` column.
2. Change `tools/mfc/apply_msvc500_library_region.py` so accepted FID rows write:
   - `symbol`: exact FID/decorated linker name when available.
   - `name`: friendly display/match name.
   - `type`: keep the existing `function` value; library ownership is represented by
     `// LIBRARY` markers / reviewed library identities (the model).
3. Preserve existing source-curated `name` values for library rows when they are
   friendlier than the FID decorated name.
4. Keep pushing friendly names to Ghidra, not decorated names, unless the decorated
   name is the only available identity.
5. Re-run:

```text
just apply-msvc500-library-region --apply
just sync-ownership
just regen-stubs
just build
just compare 0x4885d0
just stats
```

Expected effect for the `CPtrList::AddHead` case: reccmp should pair
`orig 0x0060201d` with `recomp 0x00472736` by exact `symbol`, then the wrapper call
target should render through the matched entity's friendly computed name rather than
as two different unresolved names.
