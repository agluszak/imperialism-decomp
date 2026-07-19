#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653248
class TCivMgr : public TObject {
public:
  DECLARE_DYNCREATE(TCivMgr)
  virtual ~TCivMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual bool HandleCivilianTileSelectionOrReportClick(short nTileIndex,
                                                        short nClickMode); // slot 0x0a 0x4d2380
  virtual bool HandleCivilianTileOrderAction(short nTileIndex,
                                             short nInputHint); // slot 0x0b 0x4d26d0
  virtual void RelinkCivilianOrderTileAndInvalidateMapTiles(
      short nNewTileIndex, class TCivUnit* pCivOrderEntry); // slot 0x0c 0x4d4310
  virtual void DispatchSelectedUnitToGlobalMapStateHandler(
      class TCivUnit* pUnitOrderEntry); // slot 0x0d 0x4d2270
  // Non-virtual order-action helper (0x4d3a60); dispatched from the slot 0x0b virtual
  // HandleCivilianTileOrderAction via thunk_HandleEngineerConstructionAction (0x406ccb).
  bool HandleEngineerConstructionAction(short nTileIndex);

  // Selection helpers (0x4d2c60/0x4d2cf0/0x4d2d30). These were previously modeled on a
  // duplicate class "TSelectedCivilianOrderState"; the global at 0x6a43dc is this
  // TCivMgr instance (same 0xc-byte object, same selectedEntry slot, and its vtable
  // dispatches match the slots declared above).
  void SetActiveCivilianSelection(class TCivUnit* entryContext, char refreshCommandPanel);
  void QueueImmediateCivilianCommandAndCycleSelection(int commandType);
  void ShowDisbandCivilianConfirmationDialog();

  // Data members (object size 0x0c, base TObject = vptr only).
  class TCivUnit* selectedEntry; // 0x4 — selected civilian order entry
  int field08;                   // 0x8

  TCivMgr();

  // 0x004d2f60. Validate whether the selected civilian (selectedEntry) can be assigned to the
  // clicked tile. (Ghidra mis-attributed this to TCivToolbar via a thunk-only caller; the `this`
  // is the TCivMgr order manager — [this+4] is selectedEntry.)
  char CanAssignCivilianOrderToTile(short nTileIndex);

  // 0x004d2960. Resolves the civilian map-click action code from current selection and tile
  // context (see cpp for the full action-code map). Ghidra mis-attributed this to TCivToolbar
  // via a thunk-only caller, same as CanAssignCivilianOrderToTile above.
  int ResolveCivilianTileOrderActionCode(short nTileIndex, short nInputHint);

  // 0x004d2930. Cursor resource id for the action code ResolveCivilianTileOrderActionCode
  // would return for this click. Same mis-attribution as above; `this` is implicitly forwarded
  // to ResolveCivilianTileOrderActionCode untouched.
  unsigned short LookupCivilianTileOrderCursorTokenByActionIndex(short nTileIndex,
                                                                 short nInputHint);

  // Maps the current tile's idle/working civilian selection state to the corresponding
  // map cursor resource id (0, 0x3f3, or 0x3f9). Real __thiscall on this manager even
  // though the body uses only global state. 0x004d2540.
  unsigned short ResolveCivilianTileSelectionOrReportActionCode(short nTileIndex, short nClickMode);

  // 0x004d2ef0. Attempts to queue a plain movement order (order type 1) for the selected
  // civilian onto nTileIndex; false if CanAssignCivilianOrderToTile rejects the tile. Same
  // mis-attribution as the functions above.
  bool TryQueueCivilianMoveOrderToTile(short nTileIndex);

  // 0x004d3070. Handles the Civilian Report dialog decision for pCivilianOrderEntry: if the
  // player confirms the queued order, does nothing; if they rescind it, computes a refund by
  // order type, credits the owner nation's treasury, clears the queued order, and rebinds
  // selection. Same mis-attribution as the functions above.
  void HandleCivilianReportDecision(class TCivUnit* pCivilianOrderEntry);
};
