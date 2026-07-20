#pragma once

#include "game/TDiplomacyMapView.h"

class TAnimator;
class TIdleMeAnimation;

// VTABLE: IMPERIALISM 0x0063efa8
class TBattleReportView : public TDiplomacyMapView {
public:
  DECLARE_DYNCREATE(TBattleReportView)
  ~TBattleReportView() override; // slot 0x01 scalar deleting dtor

  void Free() override; // slot 0x07 0x4ad560
  void HandleEvent(int commandId, TEventHandler* sourceHandler,
                   TEvent* event) override; // slot 0x0f 0x4ad7a0
  char DoIdle(int action) override;         // slot 0x13 0x4ad5a0
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override; // slot 0x35
  void DoPostCreate(int arg) override;                                                 // slot 0x37
  void ApplyRectSlot110(RECT* rectBuffer) override;                                    // slot 0x44
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                            int arg4) override; // slot 0x47 0x4adcb0

  void RefreshMapContextSelectionPanelAndInfoLabels(void* mapContextRecord);

  // 0x4ade30 (311 bytes) -- draws a small marker glyph from the strategic-map icon strip
  // for every g_pMapContextActionManager action record NOT currently selected (and with
  // placedFlag260 set), then one extra highlighted-variant pass (spriteCode262 + 1) for
  // the currently selected record (selectedReportIndex24c8). rectBuffer is an ignored
  // stack arg threaded through by the caller (ApplyRectSlot110).
  void RenderMapContextActionMarkers(RECT* rectBuffer);

  TBattleReportView();

private:
  int selectedReportIndex24c8;
  TIdleMeAnimation* transientRegistryObject24cc;
};

ASSERT_SIZE(TBattleReportView, 0x24d0);
