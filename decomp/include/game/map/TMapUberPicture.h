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
  virtual ~TMapUberPicture() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoMenuCommand(int command) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask) override;
  virtual void InvalidateMap();
  virtual void InvalidateTile(short tileIndex);
  virtual void RedrawTile(short tileIndex);
  // CenterOn/SetUpperLeft consume promoted stack dwords at these virtual boundaries.
  virtual void CenterOn(int tileIndex);
  virtual void SetUpperLeft(int tileX, int tileY);
  virtual void NoticeTile(int tileIndex);
  virtual bool IsAUnitSelected();
  virtual void DisplayInfo(bool showInfo);
  virtual void DisplayMiniMap();
  virtual void RemoveMiniMap();
  virtual void SetTradeToolSubcontrolEnabledStateByFlag(bool enabledState);

  bool invalidationFlag;
  // 0=civilian, 1=army, 2=navy, 3=none (default) -- selects categoryPages[] below.
  short activeUnitCategoryIndex;
  TZone* orderEntryContext;
  int deadStore9C;
  TNavyRoster* navyRoster;
  TOceanDialog* goodGoldTagControl;
  TMapDialog* subview2A8;
  TWorldView* subview;
  TView* categoryPages[4];
  TMiniMapView* miniMapView;

  TMapUberPicture();

  void SetMapInteractionMode(short nMode);
  void GrandCycle();
  void InvalidateMiniMap();
  void FocusOnForce(TTaskForce* pMapOrderEntry);
  void CommitPendingUiModeChangeAndRefreshViews(TView* controlOverride);
  void FocusOnZone(TZone* pMapOrderContextZone);
  void InvalidateMapRegionForEntryIfUiPassive(TZone* zone);
  bool TrySelectNextValidMapOrderEntry(bool includeCurrent);
  // Mode-guarded void sibling used by click/navigation paths.
  void NextSeaZonePlease(char includeCurrent);
  void EnterMapInteractionOverlayMode(TView* controlOverride);
  void SwitchToCivilianMode();

  void CivilianCheatClick(int orderContext);

  void ArmyCheatClick(short provinceIndex);
  void UpdateRoster();
  void CycleMapInteractionSelectionAfterHandledClick();
  void NavalIntelligenceDialog(TZone* zone, short nation, TTaskForce* cachedTaskForce);
  void InspectTaskForceDialog(TTaskForce* taskForce);
  void RunNavyPrimaryOrderCreationDialogAndApplyResults(TZone* portZone);
};
ASSERT_SIZE(TMapUberPicture, 0xc4);
