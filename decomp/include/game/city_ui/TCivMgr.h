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
  virtual ~TCivMgr() override;
  virtual bool CivilianTileClick(short nTileIndex, short nClickMode);
  virtual bool HandleCivilianTileOrderAction(short nTileIndex, short nInputHint);
  virtual void MoveAndRedrawUnit(short nNewTileIndex, class TCivUnit* pCivOrderEntry);
  virtual void SetDimming(class TCivUnit* pUnitOrderEntry);
  void CompletedOrders(class TCivUnit* order);
  bool EngineerClick(short nTileIndex);

  void SelectUnit(class TCivUnit* entryContext, bool refreshCommandPanel);

  bool ProspectorClick(short nTileIndex);
  void ResetCycle(short nationId);
  class TCivUnit* Cycle(short nationId);
  void WakeAll(int nationId);
  void OrderAndCycle(UnitOrder order);
  void DisbandSelected();

  // Data members (object size 0x0c, base TObject = vptr only).
  class TCivUnit* selectedEntry; // selected civilian order entry
  int field08;

  TCivMgr();
  void ICivMgr();

  bool CanDeployUnit(short nTileIndex);

  CivilianTileActionCodeStorage ResolveCivilianTileOrderActionCode(short nTileIndex,
                                                                   short nInputHint);

  unsigned short GetCivilianTileCursor(short nTileIndex, short nInputHint);

  unsigned short GetCivilianTileAction(short nTileIndex, short nClickMode);
  CivilianTileActionCodeStorage GetTileAction(short tileIndex, short mode);

  bool TryQueueCivilianMoveOrderToTile(short nTileIndex);

  void InfoBox(class TCivUnit* pCivilianOrderEntry);

  void ResolveCivilianDisputes();

  bool ImprovementClick(short nTileIndex);

  bool PurchaseClick(short nTileIndex);
};
ASSERT_SIZE(TCivMgr, 0xc);
