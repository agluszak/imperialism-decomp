#include "game/TShipyardView.h"

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TStaticText.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004c8200
// TShipyardView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c82a0
// TShipyardView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipyardView, TBuildingView)

// Ctor at 0x4c82c0 (`: TBuildingView() { field98 = 0; }`) is intentionally NOT claimed:
// unlike its TBuildingView siblings, our toolchain does not emit a uniquely-pairable
// out-of-line copy for it, so reccmp hard-fails to match the address. Left markerless
// rather than faking the match.
TShipyardView::TShipyardView() {}

// SYNTHETIC: IMPERIALISM 0x004c82f0
// TShipyardView::`scalar deleting destructor'
TShipyardView::~TShipyardView() {}

// FUNCTION: IMPERIALISM 0x004c8340
void TShipyardView::Free() {}

// Rebuilds the 8-slot ship-build queue UI: caches the strategic-map view system's
// active-view pointer and a bitmap surface for resource id 0x264f, then for each of
// eight 'but0'-'but7' queue-slot buttons clears its cached value and resets the
// button plus its embedded 'plus'/'minu' stepper controls to the disabled/off state.
// FUNCTION: IMPERIALISM 0x004c8390
undefined TShipyardView::OrphanRetStub_004c6fd0() {
  field98 = g_pStrategicMapViewSystem->field04;
  fieldB4 = 0;
  iconSurfaceB8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x264f);

  for (int slotIndex = 0; slotIndex < 8; ++slotIndex) {
    TControl* slotButton =
        static_cast<TControl*>(ResolveControlByTag(0x62757430u + slotIndex)); // 'but0'-'but7'
    slotButton->SetEnabled(0, 1);
    slotButton->SetState(0, 1);
    buildQueueSlotValues[slotIndex] = 0;

    TControl* plusButton = static_cast<TControl*>(slotButton->ResolveControlByTag(0x706c7573u)); // 'plus'
    plusButton->AssertValid();
    plusButton->SetState(0, 0);

    TControl* minusButton = static_cast<TControl*>(slotButton->ResolveControlByTag(0x6d696e75u)); // 'minu'
    minusButton->AssertValid();
    minusButton->SetState(0, 0);
  }

  // 14-byte style buffer: the 10-byte descriptor plus 4 explicitly zeroed tail bytes (the
  // original zeroes them once before the first Build call) -- same idiom as
  // TBattleReportView::NoOpUiLifecycleHook.
  struct {
    TUiTextStyleDescriptor desc;
    unsigned char tail[4];
  } style;
  style.tail[0] = 0;
  style.tail[1] = 0;
  style.tail[2] = 0;
  style.tail[3] = 0;

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TStaticText* title = static_cast<TStaticText*>(ResolveControlByTag(0x7469746cu)); // 'titl'
  title->AssertValid();
  title->SetTextStyleAndMaybeRefresh(&style.desc, 1);
  title->LoadUiStringAndDispatchViaVslot1C8(0x2736, 0xe, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  for (int i = 0; i < 2; ++i) {
    TStaticText* fixedLabel = static_cast<TStaticText*>(ResolveControlByTag(0x66697830u + i)); // 'fix0'/'fix1'
    fixedLabel->AssertValid();
    fixedLabel->SetTextStyleAndMaybeRefresh(&style.desc, 1);
    fixedLabel->LoadUiStringAndDispatchViaVslot1C8(0x2736, static_cast<short>(i + 0xf), 1);
  }

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xc, 0x2b6b);
  TControl* shipName = static_cast<TControl*>(ResolveControlByTag(0x736e616du)); // 'snam'
  shipName->AssertValid();
  shipName->SetTextStyleAndMaybeRefresh(&style.desc, 1);

  BuildUiTextStyleDescriptor(&style.desc, 0, 0xa, 0x2b6b);
  TControl* description = static_cast<TControl*>(ResolveControlByTag(0x64657363u)); // 'desc'
  description->AssertValid();
  description->SetTextStyleAndMaybeRefresh(&style.desc, 1);

  fieldA0 = 0;
  fieldA2 = 0;
  InitializeCityViewActionButtons(buildQueueSlotValues[0]);

  // 'sele' is a TCluster (confirmed by cross-referencing turn_event_dialog_factory.cpp,
  // which builds a real TCluster with controlTag 'sele'); byte 0x1c8 matches
  // TCluster::SetControlClassAndRefresh(int) exactly (1 arg, RET 4).
  TCluster* sele = static_cast<TCluster*>(ResolveControlByTag(0x73656c65u)); // 'sele'
  sele->AssertValid();
  sele->SetControlClassAndRefresh(0x62757430); // 'but0'
  OrphanRetStub_004c6fb0();
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c8a50
undefined TShipyardView::OrphanRetStub_004c6fb0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c8ac0
void TShipyardView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // The original dispatches on field94's real receiver class via a lookup keyed by
  // field94+0xe4+idx*4 -- its only assignment site, RefreshCityViewProductionDetails
  // (0x4cfbd0, 1748 bytes), is itself unported, so the receiver class is unresolved here
  // too -- not yet ported.
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004c8d70
void TShipyardView::InitializeCityViewActionButtons(short arg1) {}

// FUNCTION: IMPERIALISM 0x004c9150
void TShipyardView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x004c97c0
undefined TShipyardView::BuildIndustryActionCostSummaryTextByActionIndex() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c9a60
void __fastcall TShipyardView::RefreshCityViewStatusPanel(int* pCityViewDialog) {}

// FUNCTION: IMPERIALISM 0x004c9d20
undefined TShipyardView::OrphanCallChain_C1_I15_004c9d20(int param_1) {
  return 0;
}
