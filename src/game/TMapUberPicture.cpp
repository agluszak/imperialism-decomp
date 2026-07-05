#include "game/TMapUberPicture.h"

#include "game/TArmyMgr.h"
#include "game/TCivMgr.h"
#include "game/TOcean.h"
#include "game/TSimMgr.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00596900
// TMapUberPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005969c0
// TMapUberPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapUberPicture, TMapUberUberPicture)

// FUNCTION: IMPERIALISM 0x005969e0
TMapUberPicture::TMapUberPicture()
    : invalidationFlag94(1), activeUnitCategoryIndex96(3), orderEntryContext98(nullptr),
      field_0x9c(0), field_0xa0(0), goodGoldTagControlA4(nullptr), field_0xc0(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x00596a30
// TMapUberPicture::`scalar deleting destructor'
TMapUberPicture::~TMapUberPicture() {}

// FUNCTION: IMPERIALISM 0x00596a80
void TMapUberPicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x00596c60
void TMapUberPicture::Free() {}

// A shared "previous mode" layout-capture scratch buffer (0x6a45e8, BSS/zeroed) and a
// per-mode saved-layout table (0x6a4590, stride 8 = 2 ints, indexed by mode 0-3); both
// passed to CaptureLayoutF0 by SetMapInteractionMode below. Exact field semantics inside
// each 8-byte entry aren't recovered -- CaptureLayoutF0's own body isn't ported.
static int g_MapUberModeLayoutScratch_006a45e8[2] = {0};
static int g_MapUberModeLayoutTable_006a4590[4][2] = {{0}};
// A second layout-capture scratch buffer (0x6a45b8, BSS/zeroed), used the same way by
// EnterMapInteractionOverlayMode.
static int g_MapUberModeSecondaryLayoutScratch_006a45b8[2] = {0};

// FUNCTION: IMPERIALISM 0x00596cb0
void TMapUberPicture::SetMapInteractionMode(short nMode) {
  short previousMode = this->activeUnitCategoryIndex96;
  if (previousMode != nMode) {
    if (previousMode == 0) {
      g_pSelectedCivilianOrderState->SetActiveCivilianSelection(nullptr, 0);
    } else if (previousMode == 1) {
      g_pMapContextActionManager->SetActiveProvinceSelection(-1);
    }

    // Ground truth also probes ownerPanel->ResolveControlByTag('tbr1'); if present, and
    // depending on whether the OLD mode was 1 (army) or the NEW mode is 1, it resolves a
    // further ('forc'/'seas'-tagged) control, tags it, and rebuilds its caption text from
    // two concatenated TSimMgr::GetString lookups (group 0x2730, offsets 0x12/0x8 or a
    // single lookup at group 0x2732 offset 0x11) before calling
    // categoryPages[]-style NotifyActiveNationChanged(GetActiveNationId()) on it. That
    // caption-control's real class isn't recovered (its own field writes don't match any
    // modeled class), so this whole UI-caption side effect is left undone rather than
    // faked; the mode-transition/selection-state and layout-capture side effects below are
    // real.
    if (nMode == 0) {
      this->EnterMapInteractionOverlayMode(0);
    }
  }

  if (previousMode < 3) {
    categoryPages[previousMode]->CaptureLayoutF0(g_MapUberModeLayoutScratch_006a45e8, 1);
  }
  this->activeUnitCategoryIndex96 = nMode;
  if (nMode < 3) {
    categoryPages[nMode]->CaptureLayoutF0(g_MapUberModeLayoutTable_006a4590[nMode], 1);
  }
}

// FUNCTION: IMPERIALISM 0x00597340
void TMapUberPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00597600
void TMapUberPicture::vmethod_0017(int param) {}

// FUNCTION: IMPERIALISM 0x00597770
void TMapUberPicture::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x005977a0
undefined TMapUberPicture::NotifyActiveNationChanged(int param1) {
  (void)param1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00597810
void TMapUberPicture::RefreshMapOrderEntryPanel(TTaskForce* pMapOrderEntry) {
  this->SetMapInteractionMode(2);
  // Ground truth also calls ResetMapActionContextActivityAndNationFlags() here and
  // branches on its result; that helper's own role isn't recovered, so this always takes
  // the path matching pMapOrderEntry's null-ness (its real gate).
  //
  // The per-slot dispatches below (GetMinActionThresholdFromEntryChildren,
  // ExpandTaskForceTraversalDepthAndMarkDeferredNodes, CountTaskForceSelectedOrders-
  // ByNationClass -- all thiscall on pMapOrderEntry/its command descriptor --, and
  // UpdateIndustryCapabilityControlStateAndValue -- thiscall on the resolved slider
  // control) all target classes not yet recovered (TTaskForce's own field layout beyond
  // what TOcean.cpp already established, and the slider controls' concrete type), so
  // they're left as documented gaps rather than faked calling conventions; the real
  // control-resolution/AssertValid structure and quota-field reads are reproduced.
  if (pMapOrderEntry == nullptr) {
    for (int i = 0; i < 4; ++i) {
      TView* slider = this->ResolveControlByTag(0x636c7330 + i); // "0slc".."3slc"
      slider->AssertValid();
    }
    return;
  }

  char* entry = reinterpret_cast<char*>(pMapOrderEntry);
  TView* commandDescriptor = *reinterpret_cast<TView**>(entry + 0x18);
  short commandCode = *reinterpret_cast<short*>(reinterpret_cast<char*>(commandDescriptor) + 0xc);
  this->InvalidateTileMarkerAndRefreshLinkedControl(commandCode);

  for (int i = 0; i < 4; ++i) {
    TView* slider = this->ResolveControlByTag(0x636c7330 + i); // "0slc".."3slc"
    slider->AssertValid();
    (void)*reinterpret_cast<short*>(entry + 0x1e + i * 2); // per-category order quota
  }

  TView* navyControl = this->ResolveControlByTag(0x756e6176); // "unav"
  navyControl->AssertValid();
}

// FUNCTION: IMPERIALISM 0x00597950
void TMapUberPicture::SetActiveMapOrderEntry(TTaskForce* pMapOrderEntry) {
  this->SetMapInteractionMode(2);
  // Ground truth also calls InvalidateMapRegionForOrderEntry (thiscall on
  // goodGoldTagControlA4, an unrecovered control class) around the write below, once for
  // the old orderEntryContext98 value and once for the new one; left undone rather than
  // faked.
  this->orderEntryContext98 = pMapOrderEntry;
  if (pMapOrderEntry == nullptr) {
    this->RefreshMapOrderEntryPanel(nullptr);
    return;
  }
  TTaskForce* refreshedTaskForce =
      g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(pMapOrderEntry);
  this->RefreshMapOrderEntryPanel(refreshedTaskForce);
}

// FUNCTION: IMPERIALISM 0x00597a10
undefined TMapUberPicture::OrphanLeaf_NoCall_Ins23_00597a10() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598870
void TMapUberPicture::InvalidateTileMarkerChain(short tileIndex) {
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x005988c0
undefined TMapUberPicture::OrphanCallChain_C2_I18_005988c0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598910
undefined TMapUberPicture::OrphanCallChain_C2_I11_00598910(undefined4 param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598950
undefined TMapUberPicture::RefreshAfterSelectionChange() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598990
undefined TMapUberPicture::InvalidateTileMarkerAndRefreshLinkedControl(short param) {
  this->subviewAc->InvalidateTileMarkerChain(param);
  if (this->field_0xc0 != nullptr) {
    this->field_0xc0->RefreshControl();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005989d0
undefined TMapUberPicture::OrphanCallChain_C2_I16_005989d0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598a20
undefined TMapUberPicture::NotifySubviewOfSelectedTile(short entryIndex) {
  return this->subviewAc->OrphanCallChain_C2_I11_00598910(entryIndex);
}

// FUNCTION: IMPERIALISM 0x00599a50
void TMapUberPicture::EnterMapInteractionOverlayMode(int param1) {
  if (this->invalidationFlag94 != 0) {
    return;
  }
  TView* zoomControl =
      (param1 != 0) ? reinterpret_cast<TView*>(param1) : this->ResolveControlByTag(0x5a6d496e);
  zoomControl->AssertValid();
  // Ground truth also tags zoomControl->field_0x1c = 'ZmOt' (0x5a6d4f74) here when
  // zoomControl is non-null -- a raw field write on a class beyond TView, matching the
  // same "'forc'/'seas'-tagged control" attribution gap documented in
  // SetMapInteractionMode; left undone.
  this->invalidationFlag94 = 1;

  // Ground truth also calls goodGoldTagControlA4->vtable[0x1f4]() here and forwards the
  // result into subview2A8->InvalidateTileMarkerChain(...) (see the class-attribution
  // caveat on goodGoldTagControlA4's declaration); left undone.

  this->goodGoldTagControlA4->CaptureLayoutF0(g_MapUberModeLayoutScratch_006a45e8, 0);
  this->subview2A8->CaptureLayoutF0(g_MapUberModeSecondaryLayoutScratch_006a45b8, 1);
  this->subviewAc = this->subview2A8;

  // Ground truth also centers field_0xc0's cursor-marker box here: reads its own
  // +0x34/+0x38 extent, writes +0x90/+0x94/+0x98/+0x9c, and calls its RefreshControl.
  // field_0xc0's concrete class isn't recovered beyond TView (see its declaration), so
  // that final step is left undone rather than faked.
}

// FUNCTION: IMPERIALISM 0x00599cf0
void __fastcall TMapUberPicture::CreateToolWindow_00599CF0(astruct_20* this_obj) {}

// FUNCTION: IMPERIALISM 0x00599fd0
undefined TMapUberPicture::SwapToolInfoSubviewAndRefreshClipRegion() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059a180
undefined TMapUberPicture::SetTradeToolSubcontrolEnabledStateByFlag() {
  return 0;
}
