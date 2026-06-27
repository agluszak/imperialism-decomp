#pragma once

#include "game/TDiplomacyMapView.h"

class TAnimator;

// TODO(manifest): describe TBattleReportView and its role. Constructor evidence
// calls TDiplomacyMapView::TDiplomacyMapView, initializes the derived tail at
// 0x24c8..0x24cc, then installs the complete-object vftable.
// VTABLE: IMPERIALISM 0x0063efa8
class TBattleReportView : public TDiplomacyMapView {
public:
  DECLARE_DYNCREATE(TBattleReportView)
  ~TBattleReportView() override;                   // slot 0x01 scalar deleting dtor

  void Free() override; // slot 0x07 0x4ad560
  void HandleEvent(int commandId, TEventHandler* sourceHandler,
                   TEvent* event) override;                 // slot 0x0f 0x4ad7a0
  char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x4ad5a0
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           int hitArg) override; // slot 0x35
  void NoOpUiLifecycleHook(int arg) override;                                    // slot 0x37
  void ApplyRectSlot110(RECT* rectBuffer) override;                              // slot 0x44
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                            int arg4) override; // slot 0x47 0x4adcb0

  void RefreshMapContextSelectionPanelAndInfoLabels(void* mapContextRecord);

  TBattleReportView();

private:
  int selectedReportIndex24c8;
  void* transientRegistryObject24cc;
};

ASSERT_SIZE(TBattleReportView, 0x24d0);
