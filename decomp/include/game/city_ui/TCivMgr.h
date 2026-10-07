#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/civilian_domain_types.h"
#include "game/unit_domain_types.h"

// VTABLE: IMPERIALISM 0x00653248
class TCivMgr : public TObject {
public:
  DECLARE_DYNCREATE(TCivMgr)
  virtual ~TCivMgr() override; // slot 0x01 (scalar deleting destructor)
  virtual bool HandleCivilianTileSelectionOrReportClick(short nTileIndex,
                                                        short nClickMode); // slot 0x0a 0x4d2380
  virtual bool HandleCivilianTileOrderAction(short nTileIndex,
                                             short nInputHint); // slot 0x0b 0x4d26d0
  virtual void MoveAndRedrawUnit(short nNewTileIndex,
                                 class TCivUnit* pCivOrderEntry); // slot 0x0c 0x4d4310
  virtual void DispatchSelectedUnitToGlobalMapStateHandler(
      class TCivUnit* pUnitOrderEntry); // slot 0x0d 0x4d2270
  void ApplyCompletedCivWorkOrderToMapState(class TCivUnit* order);
  bool HandleEngineerConstructionAction(short nTileIndex);

  void SelectUnit(class TCivUnit* entryContext, bool refreshCommandPanel);

  bool QueueProspectingOrderAndPlayFeedback(short nTileIndex);
  void ClearCivilianSelectionHighlightsForNation(short nationId);
  class TCivUnit* SelectFirstAvailableCivilianForNation(short nationId);
  void WakeAll(int nationId);
  void OrderAndCycle(UnitOrder order);
  void DisbandSelected();

  // Data members (object size 0x0c, base TObject = vptr only).
  class TCivUnit* selectedEntry; // 0x4 — selected civilian order entry
  int field08;                   // 0x8

  TCivMgr();
  void ICivMgr();

  bool CanAssignCivilianOrderToTile(short nTileIndex);

  CivilianTileActionCodeStorage ResolveCivilianTileOrderActionCode(short nTileIndex,
                                                                   short nInputHint);

  unsigned short LookupCivilianTileOrderCursorTokenByActionIndex(short nTileIndex,
                                                                 short nInputHint);

  unsigned short ResolveCivilianTileSelectionOrReportActionCode(short nTileIndex, short nClickMode);
  CivilianTileActionCodeStorage GetTileAction(short tileIndex, short mode);

  bool TryQueueCivilianMoveOrderToTile(short nTileIndex);

  void HandleCivilianReportDecision(class TCivUnit* pCivilianOrderEntry);

  void ResolveCivilianDisputes();

  bool QueueCivilianWorkOrderWithCostCheck(short nTileIndex);

  bool PromptAndQueueDeveloperTilePurchaseOrder(short nTileIndex);
};
ASSERT_SIZE(TCivMgr, 0xc);
