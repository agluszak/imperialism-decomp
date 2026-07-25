# Imperialism save-file format

Reference for `.imp` save files and the `TStream` serialization layer they are built on.
Recovered from the retail image (listings, not decompiles) plus the Mac CodeWarrior name
oracle. Verified against a retail-derived fixture at save-format version `0x3e`.

The companion tool is `just serde-audit`, which checks every ported `ReadFrom`/`WriteTo`
against the original's stream-call sequence. Read [The desync rule](#the-desync-rule)
before touching any serializer.

## The desync rule

The save stream is **flat and unframed**: no per-record lengths, no sentinels, no
type tags outside the object sub-format. A reader that consumes the wrong number of
bytes shifts everything after it, and nothing downstream can detect or recover from it.

Two consequences that are easy to get backwards:

- **A low reccmp score does not imply a desync.** `TOcean::ReadFrom` sits below 40% with
  byte accounting that is exactly right; the gap is EH/codegen shape. `just triage`
  reports it `inconclusive`, which per AGENTS.md is not evidence of a source defect.
- **A high score does not imply correctness.** `TDiplomacyMgr::ReadFrom` looked like three
  tidy matrix reads while under-reading 2.1 KB, and `TTown::WriteTo` wrote the right
  *number* of bytes in the wrong *order* (raw block where the reader byte-swaps), so
  every resource yield came back corrupted.

`just serde-audit` measures byte accounting specifically, and is the check that matters
for save/load. Run it after touching a serializer; run `just triage` for the score.

## Byte order

**The stream is big-endian.** The Windows build shares its persisted format with the
Macintosh original, so every 16- and 32-bit field is swapped around the raw block
primitives — `TStream` itself moves bytes and does no reordering.

Helpers live in `game/core/stream_byteswap.{h,cpp}`. Two shapes appear in the image and
the choice is per call site — the listing shows which:

| Shape | Use |
| --- | --- |
| `ByteSwapShortInPlace` (0x4f2970), `SwapFirstTwoBytesInBuffer` (0x4b9340) | the original `CALL`s the helper (directly or through an ILT thunk) |
| `ReadByteSwappedShortArrayFromStream` (0x4f2a60), `WriteByteSwappedShortArrayToStream` (0x4b94a0) | out-of-line array read/write |
| `SwapShortArrayBytes`, `ReverseDwordArrayBytes`, `SwapFloat`, `WriteShortArrayElems`, `WriteIntArrayElems` (`static __inline`) | the original inlined the loop at the call site |

Forcing an inlined site through the out-of-line helper (or the reverse) changes codegen
and costs match.

`0x4f2970` and `0x4b9340` are byte-identical twins: the original emits one copy per
module that uses the helper, so the image carries two bodies for one source function. We
carry two named definitions because a `// FUNCTION:` marker binds exactly one address.

## Widths: MacApp scalars are not C++ scalars

`TStream`'s accessors carry MacApp names, and MacApp's sizes surprise C++ readers. This
table is the one to check before writing a serializer line:

| Accessor | Slot (read / write) | Bytes |
| --- | --- | --- |
| `ReadByte` / `WriteByte` | 0x40 / 0x7c | 1 |
| `ReadBoolean` / `WriteBoolean` | 0x44 / 0x80 | 1 |
| `ReadCharacter` / `WriteCharacter` | 0x48 / 0x84 | 1, widened to a short |
| `ReadInteger` / `WriteInteger` | 0x4c / 0x88 | **2** — MacApp `Integer` is 16-bit |
| `ReadLong` / `WriteLong` | 0x50 / 0x8c | 4 |
| `ReadVPoint` / `WriteVPoint` | 0x54 / 0x90 | 8 (two longs) |
| `ReadRect` / `WriteRect` | 0x58 / 0x94 | 8 |
| `ReadVRect` / `WriteVRect` | 0x5c / 0x98 | 16 |
| `ReadUnclassified16ByteRecord` / `Write…` | 0x60 / 0x9c | 16, identity unrecovered |
| `ReadPoint` / `WritePoint` | 0x64 / 0xa0 | 4 |
| `ReadIDType` / `WriteIDType` | 0x68 / 0xa4 | 4 |
| `ReadString` / `WriteString` | 0x6c / 0xa8 | 2-byte length + that many bytes |
| `ReadSharedString` / `WriteSharedString` | 0x70 / 0xac | same, into/from a `CString` |
| `ReadWordAlign` / `WriteWordAlign` | 0x74 / 0xb8 | 0 or 1, to an even offset |
| `ReadBytes` / `WriteBytes` | 0x3c / 0x78 | primitive; the size operand |
| `ReadObject` / `WriteObject` | 0xb0 / 0xb4 | polymorphic, see below |

Read slots 0x40–0x70 mirror write slots 0x7c–0xac pair for pair; that mirror is how the
mapping was recovered, and it is a useful sanity check when reading a listing.

`TStream` is a concrete base: every typed accessor above has a default body delegating to
`ReadBytes`/`WriteBytes`, which the concrete subclasses override — `TFileStream` (a
`CArchive`), `THandleStream` (growable `HGLOBAL`, usable in-process for round-trip
testing), `TCountingStream` (measures length without a buffer).

## File layout

Written by `TAmbitFileBasedDocument::DoWrite` (0x49eb30), read by `DoRead` (0x49e6a0),
reached through `CAmbitDocument::Serialize` (0x4797d0) from MFC's document open/save.

| Offset | Size | Contents |
| --- | --- | --- |
| 0x0000 | 4 | magic `AMBI` (stored little-endian, so `IBMA` on disk) |
| 0x0004 | 4 | save-format version → `g_nSaveFormatVersion` |
| 0x0008 | 4 | session slot; checked only when `multiplayerSessionRole == 2` |
| 0x000c | 0x20 | save label, e.g. `- Autosave -` |
| 0x002c | 0x1950 | per-tile owner nation tags |
| 0x197c | 0x24 | summary block: economic quarter (2), difficulty (1), active nation (1), active nation name (0x20) |
| 0x19a0 | … | the manager chain |

`DoRead` rejects a wrong magic, and any version below `0x23`, with a modal error. The
current version constant is `g_nCurrentAmbitSaveFormatVersion = 0x3e`.

The header's tile tags and summary block are written from live state but **discarded on
read** — `DoRead` reads them into a scratch buffer it immediately frees. They exist for
the save-slot browser, which reads the header without loading the game.

## Manager chain

Read in this exact order; each entry is a virtual `ReadFrom`/`WriteTo` pair.

| # | Global | Class |
| --- | --- | --- |
| 1 | `g_pGlobalUiRootController` | `TAmbitApplication` |
| 2 | `g_pSimMgr` | `TSimMgr` |
| 3 | `g_pUiAnimator` | `TAnimator` |
| 4 | `g_pNationInteractionStateManager` | `TTradeMgr` |
| 5 | `g_pDiplomacyTurnStateManager` | `TDiplomacyMgr` |
| 6 | `g_pCityOrderCapabilityState` | `TTechMgr` |
| 7 | `g_pGlobalMapState` | `TMapMgr` |
| 8 | `g_pActiveMapOrderContext` | `TOcean` |
| 9 | `g_pNavyOrderManager` | `TNavyMgr` |
| 10 | `g_pMapContextActionManager` | `TArmyMgr` |
| 11 | `g_apTerrainTypeDescriptorTable[]` | `TCountry` base; concrete `TGreatPower` / `TMinor` |
| 12 | `g_pUiRuntimeContext` | `TViewMgr` |
| 13 | `g_pStrategicMapViewSystem` | `TMacViewMgr` |
| 14 | `g_pNewsMgr` | `TNewsMgr` |
| 15 | `g_pHelpMgr` | `THelpMgr` |

After the chain, `DoRead` rebuilds each local nation's transport influence map and resets
`g_nSaveFormatVersion` to -1.

## Version gates

**Readers are gated; writers are not.** A writer always emits the current format; a
reader guards each field group added after the initial format with the version that
introduced it, leaving older saves at their constructed value. Gates must be transcribed
exactly even where the current fixture takes every branch — the reader has to keep
loading old saves.

Two shapes to expect in a listing, both of which `serde-audit` models:

- **Extra field group.** `CMP dword [g_nSaveFormatVersion], N; JLE skip` around a read.
- **Width variant.** Both arms push a different size and converge on one `CALL`, so the
  original shows a single call site where the source has an `if`/`else`
  (`TGreatPower::grantTotalCost` is 2 bytes below `0x3e`, 4 at or above). The compiler may
  also keep two separate call sites for the same source shape — that is a codegen
  decision, not a format difference.

Known gates, by introducing version: `0xa` (`TTown::activeFlag4f`), `0xb`, `0xd`, `0xe`,
`0x17`, `0x1a`, `0x1b`, `0x1d`, `0x26`, `0x27` (`TTradeMgr` row layout), `0x2e`, `0x2f`,
`0x32`, `0x34`, `0x37`, `0x3e` (`grantTotalCost` widened to 4 bytes).

## Object sub-format

The mission cluster travels as polymorphic `CObject`s rather than as inline fields:

```
TStream::ReadObject / WriteObject   (slots 0xb0 / 0xb4)
  -> TFileStream forwards to CArchive::ReadObject / WriteObject
     -> the object's CObject::Serialize override
        -> TObject::Serialize (0x485e90) wraps the CArchive back into a TFileStream
           and dispatches to the object's own ReadFrom / WriteTo
```

`CArchive` persists the **class name string and schema number**, so a class whose
`IMPLEMENT_SERIAL` name or schema differs from the original makes a retail save
unreadable no matter how correct the field code is. Thirteen classes participate:
`TObject`, `TMission`, `TNavyMission`, `TArmyMission`, `TAttackProvinceMission`,
`TInvadeMission`, `TDefendProvinceMission`, `TControlSeaZoneMission`,
`TBeachheadMission`, `TBlockadePortMission`, `TEscortMission`,
`TScatteredShipsMission`, `CDib`. Verify names and schemas against the RTTI oracle
(`just rtti-oracle`, `config/rtti_class_oracle.csv`).

## Gotchas seen in practice

- **A writer's discriminator byte is read by the container, not the object.**
  `TCityTask::WriteTo` writes `pendingFlag` before calling its base; `TCityTask::ReadFrom`
  never reads it. Both are 100%-matched — that is the original's shape, not a bug.
- **`TFileStream::GetPosition` genuinely returns 0** (0x489180, 100%-matched), so
  `ReadWordAlign` never actually skips on a file stream. Do not "fix" it; instrument the
  backing `CFile` from test-side code instead.
- **Runtime-derived fields are not persisted.** `TDiplomacyMgr`'s baseline-copy pointers
  and comparative-power rows, `TMapMgr`'s per-tile order chains, and similar caches are
  rebuilt after the load; their absence from a serializer is correct.
- **Byte count matching is necessary, not sufficient.** It proves the reader consumes the
  right amount, not that it stores the right values (`TTown`'s swapped yields) or that
  object identities resolve.
