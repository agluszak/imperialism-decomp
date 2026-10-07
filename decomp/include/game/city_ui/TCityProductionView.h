#pragma once

#include "compat.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/gfx/quickdraw_regions.h"

class TBuildingView;
struct TQuickDrawSurfaceContext;
class TCity;
class TTransFocusAnimation;

// VTABLE: IMPERIALISM 0x0064fc20
class TCityProductionView : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TCityProductionView)
  virtual ~TCityProductionView() override;
  void Free() override; // slot 0x07 0x4ba740 ReleaseCityBuildingControls
  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override;
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint, CPoint& currentPoint,
                  bool commandFlag) override;
  virtual void DrawToGWorld(RECT* destRect, TQuickDrawSurfaceContext* destContext, short offsetY,
                            short offsetX, short resourceId,
                            TQuickDrawSurfaceContext* restoreContext, int restoreFlags);
  virtual void DrawTopLevel();
  // RET 0x8 = 2 stack dwords (int + int*), not 0. slot 0x76
  virtual void InitializeCityProductionDialog(TCity* city, TView* dialogRoot);
  virtual void UpdateUnits();
  virtual void UpdateToolbar();
  virtual void CloseAndSaveWindows();
  virtual void SetBuildingPicture(short buildingSlot, short buildingType);
  virtual void UpdateFields();

#if defined(IMPERIALISM_RUNTIME_TESTS)
  bool ActivateBuildingSlotForRuntimeTest(short buildingSlot);
  TBuildingView* BuildingViewForRuntimeTest(short buildingSlot);
  TTransFocusAnimation* BuildingActionAnimationForRuntimeTest(short buildingSlot);
#endif

  TCityProductionView();

private:
  friend class TBuildingView;
  friend class TShipyardView;
  friend class TMacViewMgr;

  TCity* city;
  TView* dialogRoot;
  unsigned char padding9C[8];
  short selectedBuildingSlot;
  bool needsRefresh;
  unsigned char paddingA7;
  short clockHour;       // -1 until first drawn
  short clockMinuteMark; // minutes / 5
  TBuildingView* buildingViews[16];
  // One region handle per building slot, disposed by Free().
  RgnHandle buildingClipRegions[16];
  // Eight action groups, each with three synchronized transition animations.
  TTransFocusAnimation* buildingActionAnimations[8][3];
};

ASSERT_SIZE(TCityProductionView, 0x18c);
