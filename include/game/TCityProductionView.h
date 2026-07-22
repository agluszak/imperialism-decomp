#pragma once

#include "compat.h"
#include "game/TNoHilitePicture.h"
#include "game/quickdraw_regions.h"

class TBuildingView;
class TCity;
class TTransFocusAnimation;

// VTABLE: IMPERIALISM 0x0064fc20
class TCityProductionView : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TCityProductionView)
  virtual ~TCityProductionView() override; // slot 0x01 (scalar deleting destructor)
  void Free() override;                    // slot 0x07 0x4ba740 ReleaseCityBuildingControls
  void DoEvent(int commandId, TEventHandler* sourceHandler,
               TEvent* event) override; // slot 0x0f 0x4bc610
  void HandleCursorHoverSelectionByChildHitTestAndFallback(
      CPoint* point,
      RgnHandle hitArg) override;       // slot 0x35 0x4bafa0
  void DoPostCreate(int arg) override;  // slot 0x37 0x4ba3b0
  void Draw(RECT* rectBuffer) override; // slot 0x44 0x4ba7b0
  void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                      CPoint origin) override; // slot 0x47 0x4bc660
  void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint, CPoint& currentPoint,
                  unsigned char commandFlag) override; // slot 0x68 0x4bc870
  // slots 0x02..0x06, 0x08..0x0e, 0x10..0x34, 0x36, 0x38..0x43, and
  // 0x45..0x67 and 0x69..0x73 inherited from TNoHilitePicture.
  // RET 0x1c = 7 stack dwords; Ghidra recovered only 6. The trailing dword is the
  // palette the name promises (body still a stub). slot 0x74 0x4bac50
  virtual void BlitBitmapResourceRectWithScreenOffsetAndPalette(RECT* sourceRect, int surface,
                                                                short offsetY, short offsetX,
                                                                undefined4 context,
                                                                undefined4 flags,
                                                                undefined4 palette);
  virtual void RenderNationHeaderDateLabelWithPeriodicRefresh(); // slot 0x75 0x4badd0
  // RET 0x8 = 2 stack dwords (int + int*), not 0. slot 0x76 0x4bb7a0
  virtual void InitializeCityProductionDialog(TCity* city, TView* dialogRoot);
  virtual void UpdateUnits();         // slot 0x77 0x4bc0b0
  virtual void UpdateToolbar();       // slot 0x78 0x4bc500
  virtual void CloseAndSaveWindows(); // slot 0x79 0x4bc910
  // Mac oracle: SetBuildingPicture(short, short). The Windows body redraws the top-level
  // production view and does not read either argument. slot 0x7a 0x4bc9b0
  virtual void SetBuildingPicture(short buildingSlot, short buildingType);
  virtual void UpdateFields(); // slot 0x7b 0x4bcaf0

  TCityProductionView();

private:
  friend class TBuildingView;
  friend class TShipyardView;
  friend class TMacViewMgr;

  TCity* city94;
  TView* dialogRoot98;
  unsigned char padding9C[8];
  short selectedBuildingSlotA4;
  bool needsRefreshAtA6;
  unsigned char paddingA7;
  short currentMonthAtA8;
  short currentWeekAtAA;
  // InitializeCityProductionDialog loops over all 16 city production slots and stores
  // each constructed building page from +0xac through +0xe8. TBuildingView::Close clears
  // the indexed entry directly when the page is embedded.
  TBuildingView* buildingViewsAC[16];
  // One region handle per building slot, disposed by Free().
  RgnHandle buildingClipRegionsEC[16];
  // Eight action groups, each with three synchronized transition animations.
  TTransFocusAnimation* buildingActionAnimations12C[8][3];
};

ASSERT_SIZE(TCityProductionView, 0x18c);
