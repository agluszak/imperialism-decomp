# Field layout annotations

Headers under `include/game/*.h` carry recovered MSVC field layout as comments.
`gen_recovered_fields_from_headers`, `apply_mfc_rtti`, and `field-layout-gate`
share the grammar implemented in `tools/common/field_layout_annotations.py`.

## Recovery status

Record the recovery status directly in the class header using comment annotations:

```cpp
// LAYOUT: RECOVERED
// VTABLE: IMPERIALISM 0x0064f580
class TCity {
```

`status` can be `RECOVERED` or `IN_PROGRESS`.

**`RECOVERED`** — `just field-layout-gate` requires every non-pad data member to
carry a resolvable offset annotation, and the annotation must match the
sequential layout walk (pcpp + cxxheaderparser).


## Offset comment forms

### 1. Same-line (preferred for `recovered` classes)

```cpp
short field04; // +0x04
short needCapA6; // +0xa6
TCity* city; // 0x894 — city production state
```

Use `+0xNN` or `0xNN`. Do not put a `..` range on the same line as the field.

### 2. Previous-line block range

Labels the **first** field in a contiguous span. The comment must include a
description dash after the range (`—`, `--`, or ` - `):

```cpp
// +0x7e..+0xac — per-resource reserved amounts
short reservedByType7e[0x17];

// 0xe4..0x1d8 — owned order objects
void* orderSlotsE4[0x3d];
```

Do **not** use this form for inherited-base diagrams that describe memory owned
by a base class — those lines must not use a trailing dash:

```cpp
// 0x04..0x90 (identity strings...) now live on the TCountry base.
TForeignMinister* foreignMinister;  // starts at TGreatPower+0x94 via curated.layout.base_offset
```

### 3. Previous-line block start

```cpp
// 0x894 — city production state
TCity* city;
```

### 4. Range naming the field (legacy)

```cpp
// 0xB6..0xE4; fieldB6[0x15]/[0x16] occupy 0xE0/0xE2.
short fieldB6[0x17];
```

## Pad fields

Members named `pad*` or `padding_*` are layout spacers. They advance the
sequential cursor but are not emitted as recovered fields and do not need
offset comments.

## Derived-class prefix

When a class inherits a documented prefix (e.g. `TGreatPower` after `TCountry`),
do not re-annotate base-owned bytes in the derived header.


## Closed loop

```bash
just gen-recovered-fields-from-headers --class TCity   # suggestions
just field-layout-gate                               # annotation policy
just apply-mfc-rtti --apply                          # Ghidra struct fields
just ghidra-decomp-check                             # decompile regression
```
