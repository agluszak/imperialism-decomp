#pragma once

#include "compat.h"

#include "game/ui_widgets/TMapUberUberPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/mfc.h"

class TTaskForce;
class TZone;
class TNavyRoster;
class TWorldView;
class TMiniMapView;
class TMapDialog;
class TOceanDialog;

// VTABLE: IMPERIALISM 0x00668f08
class TMapUberPicture : public TMapUberUberPicture {
public:
  DECLARE_DYNCREATE(TMapUberPicture)
  virtual ~TMapUberPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;        // slot 0x07 0x596c60
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                    // slot 0x0f 0x00597340
  virtual void DoMenuCommand(int param) override;                  // slot 0x11 0x597600
  virtual void DoKeyEvent(TToolboxEvent* event) override;          // slot 0x12 0x597770
  virtual void DoPostCreate(int arg) override;                     // slot 0x37 0x596a80
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask) override; // slot 0x74 0x5977a0
  virtual void InvalidateMap(); // slot 0x75 0x598950
  virtual void InvalidateTile(short tileIndex); // slot 0x76 0x598870
  virtual void RedrawTile(short tileIndex); // slot 0x77 0x5988c0
  // CenterOn/SetUpperLeft consume promoted stack dwords at these virtual boundaries.
  virtual void CenterOn(int tileIndex);                                   // slot 0x78 0x598990
  virtual void SetUpperLeft(int tileX, int tileY);                        // slot 0x79 0x5989d0
  virtual void NoticeTile(int tileIndex);                                 // slot 0x7a 0x598a20
  virtual bool HasActiveMapInteractionSelection();                        // slot 0x7b 0x597a10
  virtual void PrepareAndRenderMapOverlayMode(unsigned char overlayMode); // slot 0x7c 0x598910
  virtual void DisplayMiniMap(); // slot 0x7d 0x599cf0
  virtual void RemoveMiniMap();  // slot 0x7e 0x599fd0
  virtual void SetTradeToolSubcontrolEnabledStateByFlag(bool enabledState); // slot 0x7f 0x59a180

  bool invalidationFlag;
  // 0=civilian, 1=army, 2=navy, 3=none (default) -- selects categoryPages[] below.
  short activeUnitCategoryIndex;
  TZone* orderEntryContext;
  int deadStore9C;
  TNavyRoster* navyRosterA0;
  TOceanDialog* goodGoldTagControl;
  TMapDialog* subview2A8;
  TWorldView* subview;
  TView* categoryPages[4];
  TMiniMapView* miniMapView;

  TMapUberPicture();

  void SetMapInteractionMode(short nMode);
  void GrandCycle(); // 0x5999c0, Mac oracle
  void InvalidateMiniMap();
  void RefreshMapOrderEntryPanel(TTaskForce* pMapOrderEntry);
  void CommitPendingUiModeChangeAndRefreshViews(TView* controlOverride);
  void SetActiveMapOrderEntry(TZone* pMapOrderContextZone);
  void InvalidateMapRegionForEntryIfUiPassive(TZone* zone);
  bool TrySelectNextValidMapOrderEntry(bool includeCurrent);
  // Mode-guarded void sibling used by click/navigation paths. 0x00599770.
  void SelectNextValidMapOrderEntryFromCursor(char includeCurrent);
  void EnterMapInteractionOverlayMode(TView* controlOverride);
  void ResetMapInteractionToCivilianMode();

  void CreateCivilianWorkOrderAndRegisterSelection(int orderContext);

  void PromptAndQueueMilitaryProvincePurgeOrders(short provinceIndex);
  void UpdateRoster();
  void CycleMapInteractionSelectionAfterHandledClick();
  void NavalIntelligenceDialog(TZone* zone, short nation, TTaskForce* cachedTaskForce);
  void InspectTaskForceDialog(TTaskForce* taskForce);
  void RunNavyPrimaryOrderCreationDialogAndApplyResults(TZone* portZone);
};
ASSERT_SIZE(TMapUberPicture, 0xc4);
