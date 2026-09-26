# Army stacks and military-unit references

`TArmyStack` is a `0x1c`-byte object with an owned singly linked list. Each
separately allocated eight-byte node contains a non-owning `TMilitaryUnit*`
and the next node pointer. Insertion (`0x004a7b20`) allocates eight bytes;
removal (`0x004a7ba0`) and `Free` (`0x004a7c20`) delete nodes without deleting
units. The signed word at `+0x0a` is `unitCountA`: insertion increments it,
removal decrements it, and `WriteTo` serializes it as two bytes.

The Mac oracle has `TArmyStack::AddUnit(TMilitaryUnit*)`, `AddUnit(short)`, and
`RemoveUnit(TMilitaryUnit*)` in
`vendor/macos_codewarrior/evidence/symbols.csv`. Windows stack producers take
units from a country's military list or a province's stationed military chain.
Military attributes in stack combat routines provide independent payload-type
evidence. The shared `TUnit::nextAtLocation14` remains a base-unit link because
civilian units also use it; the cast stays at that separate list boundary.

## Roster serialization

The short overload at `0x004a7a40`, named `AddUnitByRosterId` in this source,
compares the short argument with `TUnit::unitRosterId1A`, not the unit kind at
`+0x04`. It prepends the first matching country military unit and leaves the
stack unchanged if none matches. Its allocation and failure reporting are the
same as `AddUnitToChainHead`.

`ReadFrom` (`0x004a77b0`) reads a signed word count, then that many roster IDs
with an integer loop counter. It resolves each ID and prepends each match.
It does not clear existing nodes or overwrite `unitCountA` with the stream
count; missing IDs and pre-existing nodes therefore retain the retail behavior.
Construction (`0x004a76f0`) initializes only the head and cursor; `IArmyStack`
(`0x004a7770`) initializes the count and stack identity fields.

`WriteTo` (`0x004a7960`) writes the identity fields, count, and list's roster
IDs in their original widths and order. At `0x004a79d2..0x004a79e3` the ID is
copied before virtual `WriteBytes` receives its address. The source preserves
this snapshot rather than handing a stream the unit's live field address.
Both stream methods finish by clearing the stack's shared cursor.

## Shared traversal and existing operations

The cursor helpers at `0x004a3b70` and `0x004a3b90` reset and advance
`cursor18`; advancement reads the current cursor after the preceding unit
operation. Callers use those helpers instead of caching a private next node.
A null payload stops traversal just as in retail. `UnitsFighting`
(`0x004a8330`) leaves the cursor on its first eligible unit, or exhausts it.
It requires strength above half the signed strength snapshot and battle bit 2
clear. The manager's combat eligibility scans use exactly this predicate and
cursor behavior.

Stack formation, battle-side construction, movement, and battle completion
reuse the existing initialization, insertion, composition, reseating, and
growth methods. Composition still consumes one random value per stack after
its class scan. Growth still narrows the sum to a signed word before applying
the upper cap of 400. Insertion retains the nil-pointer dialog and
`UArmyMgr.cpp:0xbeb` failure path.

The post-battle method (`0x004a5ca0`) receives `sideWonFlag` as an unsigned
byte. It forwards the argument to the report routine, which also consumes a
byte, then tests `BL` at `0x004a5ccb`. No other part of the argument is read.
The caller `TArmyBattle::EndBattle` (`0x005a5320`) already takes an unsigned byte.
The declaration and definition use that same width; four-byte stack slots and
`ret 0x10` are unchanged.

Two superficially similar paths stay separate:

- `ReseatChainUnitsAndClearOrders` (`0x004a7d20`) calls `MoveTo` before clearing
  orders. `RelocateStackUnitsToStackTile` (`0x004a37b0`) clears orders first,
  and calls `MoveTo` only when the tile differs.
- `InitializeStrategicBattle` (`0x004a7d90`) caches the first unit's fort
  penalty. The manager's initialization at `0x004a3830` looks it up for each
  unit and stops on a zero penalty before modifying that unit.

## Military path arrays

`TMilitaryUnit` contains two distinct arrays of three signed tile words at
`+0x28` and `+0x2e`; its stream routines transfer each as six bytes. `ClearPath`
(`0x005c3190`) writes array 1's element, then array 2's element, for indices
0 through 2, reading `tileIndex06` for each assignment. Indexing the named
arrays preserves that order without pointer arithmetic outside either array.
