# Map Civilian Orders Plan

Date: 2026-02-15

## Goal

Make map-order decompilation legible and confirm where civilian orders are stored/committed/persisted.

## Confirmed So Far

- Click dispatch chain is identified and renamed:
  - `HandleMapClickByInteractionMode @ 0x005964b0`
  - `TryHandleMapContextAction @ 0x0055a020`
  - `GetMapContextActionCode @ 0x00559a70`
  - `TryQueueMapOrderFromTileAction @ 0x0055a160`
  - `OpenMapEntryOrderDialog @ 0x00597f80`
- Active map-order entry pointer:
  - `GetActiveMapOrderEntry @ 0x005979f0` -> `DAT_006A3FBC + 0x14`
- Order commit path identified:
  - `RebuildMapOrderEntryChildren @ 0x00553f10`
  - `MoveMapOrderEntryToQueueHeadIfValid @ 0x00557080`
  - `FinalizeQueuedMapOrderEntry @ 0x005642e0`
- Entry command fields written in queue path:
  - `entry + 0x08` command type
  - `entry + 0x0C` command target/context
- Global queue head used by commit:
  - `g_pNavyOrderManager + 0x04`
- Global save/load integration confirmed:
  - `LoadGlobalSystemsFromSave @ 0x0049e6a0` (vfunc `+0x18` deserialize pass)
  - `SaveGlobalSystemsToStream @ 0x0049eb30` (vfunc `+0x14` serialize pass)
  - includes both `g_pActiveMapContextState` and `g_pNavyOrderManager`
- Improvement-order cash timing confirmed for two order bits:
  - `QueueMapImprovementOrderBit10` sets tile bit `0x10`, deducts `2000` at queue time
  - `QueueMapImprovementOrderBit04` sets tile bit `0x04`, deducts `3000` at queue time
- Handler/token anchors identified:
  - `g_aMapImprovementOrderVtable @ 0x006588F0`
  - `g_awMapContextActionLabelTokenByCommand @ 0x0065C2F0`
- Command resolver coverage:
  - `ResolveMapOrderCommandFromActionContext` returns `0x0C/0x0D/0x0E/0x0F` (+ fallback `0x01`)
  - `ResolveMapOrderCommandFromProvinceContext` returns `0x10` (+ fallback `0x01`)
- Engineer transport bit mapping confirmed:
  - `bit 0x04` = port marker/pending
  - `bit 0x10` = rail marker/pending
  - anchored by `DumpAndResetMapScriptState` (`port %d` / `rail %d` log lines)

## Next Steps

1. Confirm civilian-only branch mapping
- Prove which tile classes/actions map to civilian units (vs naval/port paths).
- Tie `action code 11` dialog path to civilian type ids and icon ids `400..426`.

2. Decode entry structure by offsets
- Name key fields for active entry object (`+0x08`, `+0x0C`, `+0x10`, `+0x14`, `+0x1C`, `+0x1E`, `+0x28`, `+0x2C`).
- Resolve child-node structure used by `RebuildMapOrderEntryChildren`.

3. Find save/load handlers for map orders
- Done at global level (save/load pass includes active context + order manager).
- Next: isolate civilian-specific sublists/fields inside serialized payload.

4. Civilian order semantics
- Map command type values (`0xC..0x10` branches observed in queue path) to concrete civilian actions.
- Extend deduction timing beyond the two confirmed improvement bits (`0x04`, `0x10`).
- Resolve slot `7/8/9` handlers in `g_aMapImprovementOrderVtable` to concrete in-game improvement names.
- Tie command IDs to exact UI verbs (build rail, build port, depot/hub variants) via label token decode.

5. Ghidra readability pass
- Replace remaining `iVar*/uVar*` locals in core functions.
- Rename critical DAT_* globals used by map-order flow.
- Add final plate/inline comments at commit and mode-switch decision points.

## Checklist

- [x] Dispatch chain renamed
- [x] Active entry pointer location found
- [x] Core commit queue functions identified
- [x] Save/load path touching order manager confirmed
- [x] Cash deduction timing confirmed for improvement bit-0x04 and bit-0x10
- [x] Command-id branches (`0x0C..0x10`) located and documented
- [x] Rail vs port bit semantics confirmed (0x10 rail, 0x04 port)
- [ ] Civilian-specific action mapping confirmed
- [ ] Entry structure fully typed/named
- [ ] Save/load fields mapped to civilian-only order entries
- [ ] Resource/cash deduction timing confirmed for all civilian command types
