#include "game/TShipFractionCluster.h"

#include "game/TTechMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0044a720
// TShipFractionCluster::`scalar deleting destructor'
TShipFractionCluster::~TShipFractionCluster() {}
// SYNTHETIC: IMPERIALISM 0x00568cd0
// TShipFractionCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00568d50
// TShipFractionCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipFractionCluster, TCluster)

// FUNCTION: IMPERIALISM 0x0044a6f0
TShipFractionCluster::TShipFractionCluster() {}

// FUNCTION: IMPERIALISM 0x00568d70
void TShipFractionCluster::NoOpUiLifecycleHook(int arg) {
  TCluster::NoOpUiLifecycleHook(arg);

  field8c = OwnerPanel()->ResolveControlByTag(kControlTagMain);
  field8c->AssertValid();

  TView* shipControl = ResolveControlByTag(kControlTagShip);
  shipControl->AssertValid();

  short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
  if (slot != 0) {
    // The original also calls shipControl's own vtbl slot 0x1c8 (LoadUiStringAndDispatch
    // ViaVslot1C8-shaped) here with a computed (slot + 0x5e6, 0) argument pair -- exact
    // group/index semantics not resolved, so left unmodeled.
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2716, static_cast<short>(slot + 1),
                                                          controlTag);
    SetEnabled(1, 1);
  } else {
    SetEnabled(0, 1);
    SetControlHoverHelpText(CString(g_pShipFractionSharedText_0065c830), this);
  }

  // The original then resolves an 'arro' control into field90, writes field88 = 1, and
  // calls the currently-unowned 251-byte UpdateIndustryCapabilityControlStateAndValue
  // (0x568f90) -- not yet ported.
}

// FUNCTION: IMPERIALISM 0x00568eb0
void TShipFractionCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
}
