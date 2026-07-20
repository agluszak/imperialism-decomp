#include "game/TShipFractionCluster.h"

#include "game/TTechMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0044a6f0
TShipFractionCluster::TShipFractionCluster() {}

// SYNTHETIC: IMPERIALISM 0x0044a720
// TShipFractionCluster::`scalar deleting destructor'
TShipFractionCluster::~TShipFractionCluster() {}
// SYNTHETIC: IMPERIALISM 0x00568cd0
// TShipFractionCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00568d50
// TShipFractionCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipFractionCluster, TCluster)

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

  field90 = static_cast<TStaticText*>(ResolveControlByTag(kControlTagArro));
  field88 = 1;
  UpdateIndustryCapabilityControlStateAndValue(0, -1);
}

// FUNCTION: IMPERIALISM 0x00568eb0
void TShipFractionCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
}

// The original names this via a stale/reused symbol ("TToolBarCluster::..."); confirmed as
// a real TShipFractionCluster method by receiver evidence (ResolveControlByTag(kControlTagShip),
// field88/field90 matching this class's own layout). p1/p2 come from the caller as literal
// (0, -1); field88 gates whether the ship/arrow controls are currently enabled, field94 is
// the theme code applied to field90 when p1 is nonzero.
// FUNCTION: IMPERIALISM 0x00568f90
void TShipFractionCluster::UpdateIndustryCapabilityControlStateAndValue(int p1, int p2) {
  TView* shipControl = ResolveControlByTag(kControlTagShip);
  if (p1 != 0) {
    if (field88 == 0) {
      short slot = GetEnabledIndustryCapabilitySlotByClass(static_cast<short>(controlTag - 0x7330));
      shipControl->SetEnabled(1, 1);
      field90->SetEnabled(1, 1);
      LoadUiStringByGroupAndIndexToGlobalControlTag(0x2716, static_cast<short>(slot + 1),
                                                    controlTag);
    }
  } else if (field88 != 0) {
    shipControl->SetEnabled(0, 1);
    field90->SetEnabled(0, 1);
    SetControlHoverHelpTextAltEntry(CString(g_pShipFractionSharedText_0065c830), this);
  }

  RefreshControl();
  field88 = static_cast<short>(p1);
  field94 = static_cast<short>(p1);
  if (p2 > -1) {
    field94 = static_cast<short>(p2);
  }
  if (p1 > 0) {
    field90->SetTextThemeCodeAndMaybeRefresh(field94, 1);
  }
}
