#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653248
class TCivMgr : public TObject {
public:
  DECLARE_DYNCREATE(TCivMgr)
  virtual ~TCivMgr() override; // slot 0x01 (scalar deleting destructor)
  virtual bool HandleCivilianTileSelectionOrReportClick(short nTileIndex,
                                                        short nClickMode); // slot 0x0a 0x4d2380
  virtual bool HandleCivilianTileOrderAction(short nTileIndex,
                                             short nInputHint); // slot 0x0b 0x4d26d0
  virtual void RelinkCivilianOrderTileAndInvalidateMapTiles(
      short nNewTileIndex, class TCivUnit* pCivOrderEntry); // slot 0x0c 0x4d4310
  virtual void DispatchSelectedUnitToGlobalMapStateHandler(
      class TCivUnit* pUnitOrderEntry); // slot 0x0d 0x4d2270
  // Apply a completed civilian work order to the map and dispatch the required redraws.
  // 0x004d4390, real __thiscall on g_pSelectedCivilianOrderState.
  void ApplyCompletedCivWorkOrderToMapState(class TCivUnit* order);
  // Non-virtual order-action helper (0x4d3a60); dispatched from the slot 0x0b virtual
  // HandleCivilianTileOrderAction via thunk_HandleEngineerConstructionAction (0x406ccb).
  bool HandleEngineerConstructionAction(short nTileIndex);

  // Selection helpers (0x4d2c60/0x4d2cf0/0x4d2d30). These were previously modeled on a
  // duplicate class "TSelectedCivilianOrderState"; the global at 0x6a43dc is this
  // TCivMgr instance (same 0xc-byte object, same selectedEntry slot, and its vtable
  // dispatches match the slots declared above).
  void SetActiveCivilianSelection(class TCivUnit* entryContext, char refreshCommandPanel);
  // Clear highlighted (mode 3) civilian entries in the nation's tracked-object list.
  // 0x004d20e0, __thiscall.
  void ClearCivilianSelectionHighlightsForNation(short nationId);
  // Select the first idle civilian entry in the nation's tracked-object list, dispatch it
  // to the map state, and consume any pending completion sound/advisor marker.
  // 0x004d2160, __thiscall.
  class TCivUnit* SelectFirstAvailableCivilianForNation(short nationId);
  // Map hotkey 'W': clear every actionable civilian order mode for `nationId`, then
  // advance the map interaction selection when no selection remains. 0x004d49f0.
  void ClearNationCivilianActionModesAndCycleSelection(int nationId);
  void QueueImmediateCivilianCommandAndCycleSelection(int commandType);
  void ShowDisbandCivilianConfirmationDialog();

  // Data members (object size 0x0c, base TObject = vptr only).
  class TCivUnit* selectedEntry; // 0x4 — selected civilian order entry
  int field08;                   // 0x8

  TCivMgr();
  // Mac name oracle: ICivMgr. The Windows body is intentionally empty; the setup
  // lifecycle still calls this second-phase initializer after construction.
  void ICivMgr();

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

  // Mac oracle: ResolveCivilianDisputes. For each tile with competing developer purchase
  // orders, picks the entrant with the best standing toward the tile owner (random tie
  // break), cancels/refunds the others, and queues land-sale notices. 0x004d4740.
  void ResolveCivilianDisputes();

  // 0x004d3310. Checks the active nation's civilian work-order budget
  // (diplomacyBudgetBase/10 + treasuryValue10, floored at 0) against the tile's cost class,
  // and if affordable queues the order on selectedEntry (sound cue, ~0.5s message-pumped
  // pause, completion marker, immediate treasury deduction); otherwise shows a localized
  // "can't afford" message built from NumToCurrency + GetString(0x2745, 8).
  bool QueueCivilianWorkOrderWithCostCheck(short nTileIndex);

  // Mac Strings.rsrc kStrCivMgr identifies the group 0x274d prompt as "Purchase Land
  // to Develop". Confirms the city/cost-formatted purchase, queues order type 13,
  // deducts the calculated tile cost, and refreshes the nation indicator. 0x004d3610.
  // The original TCivToolbar attribution was wrong: this+4 is selectedEntry and the
  // receiver's virtual slot 0x0c is RelinkCivilianOrderTileAndInvalidateMapTiles.
  bool PromptAndQueueDeveloperTilePurchaseOrder(short nTileIndex);
};
