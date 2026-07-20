#include "game/TPurchaseCluster.h"

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
void TPurchaseCluster::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                            int arg4) {}

// FUNCTION: IMPERIALISM 0x004cc490
void TPurchaseCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagLaro) {
      field88->SetControlValue(UpdateCityViewValueControl() - 1);
    } else if (sourceHandler->controlTag == kControlTagRaro) {
      field88->SetControlValue(UpdateCityViewValueControl() + 1);
    }
    // The original also calls SetCityViewValueControlAmount(field88's own +0x4 short, 1)
    // here for either tag branch -- field88's concrete class beyond the shared
    // TEventHandler::SetControlValue slot (and that +0x4 field) is unresolved, so left
    // unmodeled.
  }
  TCluster::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cc550
void TPurchaseCluster::SetCityViewValueControlAmount(short nValue, char redrawFlag) {
  TView* valueControl = ResolveControlByTag(kControlTagValu);
  if (valueControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUCityViews_00696650, 0x781);
  }
  // TODO: dispatches through valueControl's own vtable slot 0x1e4 with (nValue, 0) --
  // byte-offset 0x1e4 coincides with TDeluxeText::ApplyTextStyleDescriptorAndMaybeRefresh
  // elsewhere, but that method takes a style-descriptor pointer, not a plain value, so
  // valueControl is NOT a TDeluxeText despite the matching offset (same "same slot,
  // different class" trap flagged repeatedly this session). Its concrete class is
  // unresolved, so the value-set call and the conditional redraw tail (invalidate rect +
  // refresh via ownerContext's own slot 0x1d8) are left unmodeled rather than guessed.
}

// FUNCTION: IMPERIALISM 0x004cc640
undefined TPurchaseCluster::UpdateCityViewValueControl() {
  return 0;
}
