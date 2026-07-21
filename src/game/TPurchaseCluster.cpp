#include "game/TPurchaseCluster.h"

#include "game/TAmtBar.h"
#include "game/TBuildingView.h"
#include "game/TEventHandler.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x004cc300
// TPurchaseCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cc3a0
// TPurchaseCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPurchaseCluster, TCluster)

// FUNCTION: IMPERIALISM 0x004cc3c0
TPurchaseCluster::TPurchaseCluster() : TCluster(), field88(0) {}

// SYNTHETIC: IMPERIALISM 0x004cc3f0
// TPurchaseCluster::`scalar deleting destructor'
TPurchaseCluster::~TPurchaseCluster() {}

// FUNCTION: IMPERIALISM 0x004cc440
undefined TPurchaseCluster::OrphanCallChain_C1_I08_004cc440(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cc470
void TPurchaseCluster::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point,
                                                            TToolboxEvent* event, CPoint origin) {}

// FUNCTION: IMPERIALISM 0x004cc490
void TPurchaseCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagLaro) {
      field88->SetEnable(static_cast<unsigned char>(UpdateCityViewValueControl() - 1));
    } else if (sourceHandler->controlTag == kControlTagRaro) {
      field88->SetEnable(static_cast<unsigned char>(UpdateCityViewValueControl() + 1));
    }
    SetCityViewValueControlAmount(static_cast<short>(field88->field04), 1);
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cc550
void TPurchaseCluster::SetCityViewValueControlAmount(short nValue, char redrawFlag) {
  // 'valu' is a TAmtBar (already the established typing at this exact tag in
  // TProductionCluster.cpp); confirmed here by TAmtBar's own SetControlValueSlot1E4(int,
  // int) matching this callsite's slot 0x1e4 dispatch and (nValue, 0) argument shape exactly
  // -- unlike the byte-coincident TDeluxeText::ApplyTextStyleDescriptorAndMaybeRefresh at the
  // same offset, which takes a style-descriptor pointer, not a plain value.
  TAmtBar* valueControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagValu));
  if (valueControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0x781);
  }
  valueControl->SetControlValueSlot1E4(nValue, 0);
  if (redrawFlag == 0) {
    return;
  }

  RECT bounds;
  bounds.left = valueControl->ownerLocalX + ownerLocalX;
  bounds.top = valueControl->ownerLocalY + ownerLocalY;
  bounds.right = bounds.left + valueControl->frameWidth34;
  bounds.bottom = bounds.top + valueControl->frameHeight38;
  RECT copiedBounds;
  CopyRect(&copiedBounds, &bounds);
  ownerContext->InvalidateCityDialogRectRegion(&copiedBounds, 1);
  // ownerContext is a TBuildingView (TArmoryView/TUniversityView/TShipyardView, the city-view
  // dialogs that host a TPurchaseCluster): confirmed by arity -- TBuildingView::
  // UpdateFields() at slot 0x76 (byte 0x1d8) takes zero args, matching this
  // callsite exactly, unlike the byte-coincident TWindow::GetTitle(CString*) which
  // takes one.
  static_cast<TBuildingView*>(ownerContext)->UpdateFields();
}

// FUNCTION: IMPERIALISM 0x004cc640
undefined TPurchaseCluster::UpdateCityViewValueControl() {
  return 0;
}
