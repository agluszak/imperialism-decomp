#include "game/TBattleReportView.h"

#include "game/TAnimator.h"

// GLOBAL: IMPERIALISM 0x0064dc80
// GLOBAL: IMPERIALISM 0x006a43e0
extern "C" TAnimator* g_pUiAnimator = 0;

TBattleReportView::TBattleReportView()
    : TDiplomacyMapView(), selectedReportIndex24c8(1), transientRegistryObject24cc(0) {}

// SYNTHETIC: IMPERIALISM 0x00430a30
// TBattleReportView::`scalar deleting destructor'
TBattleReportView::~TBattleReportView() {}
IMPLEMENT_DYNCREATE(TBattleReportView, TDiplomacyMapView)

// FUNCTION: IMPERIALISM 0x004acb60
void TBattleReportView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004ad560
void TBattleReportView::Free() {
  if (transientRegistryObject24cc != 0) {
    g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(
        *reinterpret_cast<int*>(reinterpret_cast<char*>(transientRegistryObject24cc) + 0x18));
  }
  TDiplomacyMapView::Free();
}

// FUNCTION: IMPERIALISM 0x004ad5a0
char TBattleReportView::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ad7a0
void TBattleReportView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  (void)event;
}

// FUNCTION: IMPERIALISM 0x004adc80
void TBattleReportView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                            int hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x004adcb0
void TBattleReportView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                             int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}

// FUNCTION: IMPERIALISM 0x004ade00
void TBattleReportView::ApplyRectSlot110(RECT* rectBuffer) {
  TDiplomacyMapView::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x004adfc0
void TBattleReportView::RefreshMapContextSelectionPanelAndInfoLabels(void* mapContextRecord) {
  (void)mapContextRecord;
}
