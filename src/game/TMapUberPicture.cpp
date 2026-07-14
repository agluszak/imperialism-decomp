#include "game/TMapUberPicture.h"

#include "game/quickdraw_regions.h"
#include "game/TAmbitApplication.h"
#include "game/TAnimator.h"
#include "game/TArmyMgr.h"
#include "game/TCivMgr.h"
#include "game/TMiniMapView.h"
#include "game/TOcean.h"
#include "game/TSimMgr.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

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

// Clears every global backref to the map picture (view-manager slot, animator slot, app
// root's edge-scroll/active-content) before the shared clip-region teardown; the original
// tail-jumps straight to TOffLimitsPicture::Free (0x573900), skipping the intermediate
// TMapUberUberPicture::Free.
// FUNCTION: IMPERIALISM 0x00596c60
void TMapUberPicture::Free() {
  if (g_pUiRuntimeContext != 0) {
    g_pUiRuntimeContext->mapUberPictureF0 = 0;
  }
  if (g_pUiAnimator != 0) {
    g_pUiAnimator->field2c = 0;
  }
  static_cast<TAmbitApplication*>(g_pGlobalUiRootController)->edgeScrollTarget48 = 0;
  g_pGlobalUiRootController->field28 = 0;
  TOffLimitsPicture::Free();
}

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
    // categoryPages[]-style AutoScrollByEdgeMask(GetActiveNationId()) on it. That
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
undefined TMapUberPicture::AutoScrollByEdgeMask(short edgeMask) {
  (void)edgeMask;
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
void TMapUberPicture::SetActiveMapOrderEntry(TZone* pMapOrderContextZone) {
  this->SetMapInteractionMode(2);
  // Ground truth also calls InvalidateMapRegionForOrderEntry (thiscall on
  // goodGoldTagControlA4, an unrecovered control class) around the write below, once for
  // the old orderEntryContext98 value and once for the new one; left undone rather than
  // faked.
  this->orderEntryContext98 = pMapOrderContextZone;
  if (pMapOrderContextZone == nullptr) {
    this->RefreshMapOrderEntryPanel(nullptr);
    return;
  }
  TTaskForce* refreshedTaskForce =
      g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(
          pMapOrderContextZone);
  this->RefreshMapOrderEntryPanel(refreshedTaskForce);
}

// Reports whether the active unit category (0=civilian, 1=army, 2=navy) currently has a
// selection/pending order to act on -- used by TArmyMgr::ComputeMapCursorStateIndex to
// gate map-click cursor state. 68 bytes, ground-truth-confirmed via decompile.
// FUNCTION: IMPERIALISM 0x00597a10
bool TMapUberPicture::OrphanLeaf_NoCall_Ins23_00597a10() {
  switch (this->activeUnitCategoryIndex96) {
  case 0:
    return g_pSelectedCivilianOrderState->selectedEntry != nullptr;
  case 1:
    return g_pMapContextActionManager->pendingMapActionIndex != -1;
  case 2:
    return g_pActiveMapOrderContext->selectedTaskForce14 != nullptr;
  default:
    return false;
  }
}

// Cycles map interaction selection to the next civilian/province/map-order candidate after
// a handled click. TODO: body not yet ported -- see the declaration comment in
// TMapUberPicture.h for the re-attribution evidence and why the state-machine body itself
// is deferred (packed-byte switch over ~15 unresolved helper functions).
// FUNCTION: IMPERIALISM 0x00597a80
void TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick() {}

// TODO: body not yet ported (1761-byte dialog-construction routine). Real receiver and
// arity confirmed from TToolBarCluster::TryHandleMapContextAction's case-11 call site
// (ecx = mapUberPictureF0 immediately before the call); pMapOrderEntry is the TTaskForce
// queue entry located by matching tiebreak_strength against the clicked tile index.
// FUNCTION: IMPERIALISM 0x00597f80
void TMapUberPicture::OpenMapEntryOrderDialog(TTaskForce* pMapOrderEntry) {
  // BLOCKED (still a stub): same shape as OpenMapContextActionDialogByType -- a 1761-byte
  // dialog-construction routine driving an unrecovered 100+-slot dialog-builder class via its
  // vtable. Deferred pending recovery of that builder class (see the note at 0x599090).
  (void)pMapOrderEntry;
}

// FUNCTION: IMPERIALISM 0x00598870
void TMapUberPicture::InvalidateTileMarkerChain(short tileIndex) {
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x005988c0
undefined TMapUberPicture::DispatchSelectedTileToSubviewsAndSyncTradeToolState(short entryIndex) {
  this->subviewAc->NotifySubviewOfSelectedTile(entryIndex);
  if (this->invalidationFlag94 == 0) {
    this->subview2A8->SetTradeToolSubcontrolEnabledStateByFlag(entryIndex != 0);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598910
undefined TMapUberPicture::OrphanCallChain_C2_I11_00598910(undefined4 param_1) {
  this->Refresh();
  // Ground truth also calls subviewAc->vtable[0x1a0](param_1) here -- that slot lands on
  // TMapUberPicture's own (inherited-from-TControl) DispatchPictureResourceCommand, whose
  // real arity is independently established elsewhere (TControl.cpp/TMiniMapView's own
  // override, both RET 0x14 = 5 args) as far larger than the single argument this
  // callsite pushes. That contradiction means either the slot attribution or the
  // 5-argument finding is wrong; rather than guess, this dispatch is left undone (see the
  // same DispatchPictureResourceCommand arity caveat noted where TMiniMapView's override
  // is declared).
  (void)param_1;
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
undefined TMapUberPicture::OrphanCallChain_C2_I16_005989d0(int tileX, int tileY) {
  (void)tileX;
  (void)tileY;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598a20
undefined TMapUberPicture::NotifySubviewOfSelectedTile(short entryIndex) {
  return this->subviewAc->OrphanCallChain_C2_I11_00598910(entryIndex);
}

// TODO: body not yet ported (1405-byte dialog-construction routine). Real receiver and
// arity confirmed from TToolBarCluster::TryHandleMapContextAction's case-2..8 call site
// (ecx = mapUberPictureF0 immediately before the call); actionType is the map-context
// action code minus 2 (range 0..6), cachedContext is the caller's cached map-action-
// context pointer (g_pCachedMapActionContext) forwarded for dialog continuity.
// FUNCTION: IMPERIALISM 0x00599090
void TMapUberPicture::OpenMapContextActionDialogByType(TZone* zone, int actionType,
                                                       TTaskForce* cachedContext) {
  // BLOCKED (still a stub): the body builds a dialog by loading localized "titl"/"lab1".."lab4"
  // strings via g_pSimMgr's UI-string virtual (slot 0x10) and driving a dialog-builder object
  // through a large vtable (slots 0x6d, 0x72, 0x1ac, 0x1b4, 0x1b8, 0x1c8 => a 100+-slot class).
  // That builder class is not recovered; porting faithfully without it would require banned
  // fake-callconv casts, so this is deferred pending recovery of the dialog-builder class.
  (void)zone;
  (void)actionType;
  (void)cachedContext;
}

// FUNCTION: IMPERIALISM 0x005999f0
void TMapUberPicture::ResetMapInteractionToCivilianMode() {
  EnterMapInteractionOverlayMode(0);
  SetMapInteractionMode(0);
}

// FUNCTION: IMPERIALISM 0x00599a50
void TMapUberPicture::EnterMapInteractionOverlayMode(int param1) {
  if (this->invalidationFlag94 != 0) {
    return;
  }
  TView* zoomControl =
      (param1 != 0) ? reinterpret_cast<TView*>(param1) : this->ResolveControlByTag(0x5a6d496e);
  zoomControl->AssertValid();
  if (zoomControl != nullptr) {
    zoomControl->controlTag = 0x5a6d4f74; // "ZmOt" ("Zoom Out")
  }
  this->invalidationFlag94 = 1;

  // Ground truth also calls goodGoldTagControlA4->vtable[0x1f4]() here and forwards the
  // result into subview2A8->InvalidateTileMarkerChain(...) (see the class-attribution
  // caveat on goodGoldTagControlA4's declaration); left undone.

  this->goodGoldTagControlA4->CaptureLayoutF0(g_MapUberModeLayoutScratch_006a45e8, 0);
  this->subview2A8->CaptureLayoutF0(g_MapUberModeSecondaryLayoutScratch_006a45b8, 1);
  this->subviewAc = this->subview2A8;

  if (this->field_0xc0 != nullptr) {
    this->field_0xc0->markerBoxWidth98 = g_defaultMarkerBoxWidth_006a460c;
    this->field_0xc0->markerBoxHeight9c = 8;
    this->field_0xc0->markerBoxX90 =
        this->field_0xc0->frameWidth34 / 2 - this->field_0xc0->markerBoxWidth98 - 2;
    this->field_0xc0->markerBoxY94 =
        this->field_0xc0->frameHeight38 / 2 - this->field_0xc0->markerBoxHeight9c - 2;
    this->field_0xc0->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00599cf0
undefined TMapUberPicture::CreateToolWindow_00599CF0() {
  TView* toolControl = this->ResolveControlByTag(0x746f6f6c); // "tool"
  if (toolControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0xa56);
  }

  const int kToolWindowMargin = 4;
  TMiniMapView* miniMap = new TMiniMapView();
  int offsetLayout[2] = {kToolWindowMargin, 0x31};
  int sizeLayout[2] = {0x71, 0x41};
  miniMap->InitializeUiResourceEntryFrameAndParent(nullptr, toolControl, offsetLayout, sizeLayout,
                                                   kToolWindowMargin, kToolWindowMargin, 0);
  miniMap->markerBoxX90 = miniMap->frameWidth34 / 2 - miniMap->markerBoxWidth98;
  miniMap->ownerPicture84 = this;
  miniMap->markerBoxY94 = miniMap->frameHeight38 / 2 - miniMap->markerBoxHeight9c;
  miniMap->RefreshControl();
  miniMap->SetState(1, 0);
  this->field_0xc0 = miniMap;

  RECT toolRect;
  toolRect.left = toolControl->ownerLocalX;
  toolRect.top = toolControl->ownerLocalY + kToolWindowMargin;
  toolRect.right = toolRect.left + 0x71;
  toolRect.bottom = toolRect.top + 0x41;
  RgnHandle region = NewRgn();
  RectRgn(region, &toolRect);
  UnionRgn(this->ownClipRegion90, region, this->ownClipRegion90);
  DisposeRgn(region);

  if (this->invalidationFlag94 == 0) {
    this->field_0xc0->markerBoxWidth98 = 0x20;
    this->field_0xc0->markerBoxHeight9c = 0x1c;
    this->field_0xc0->markerBoxX90 =
        this->field_0xc0->frameWidth34 / 2 - this->field_0xc0->markerBoxWidth98 - 2;
    this->field_0xc0->markerBoxY94 =
        this->field_0xc0->frameHeight38 / 2 - this->field_0xc0->markerBoxHeight9c - 2;
    this->field_0xc0->RefreshControl();
  }

  return this->SetTradeToolSubcontrolEnabledStateByFlag(0);
}

// FUNCTION: IMPERIALISM 0x00599fd0
undefined TMapUberPicture::SwapToolInfoSubviewAndRefreshClipRegion() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059a180
undefined TMapUberPicture::SetTradeToolSubcontrolEnabledStateByFlag(bool enabledState) {
  TView* toolControl = this->ResolveControlByTag(0x746f6f6c); // "tool"
  if (toolControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0xac7);
  }

  TView* seasControl = toolControl->ResolveControlByTag(0x73656173); // "seas"
  if (seasControl != nullptr) {
    seasControl->SetEnabled(enabledState, 1);
  }
  TView* yearControl = toolControl->ResolveControlByTag(0x79656172); // "year"
  if (yearControl != nullptr) {
    yearControl->SetEnabled(enabledState, 1);
  }
  TView* treaControl = toolControl->ResolveControlByTag(0x74726561); // "trea"
  if (treaControl != nullptr) {
    treaControl->SetEnabled(enabledState, 1);
  }
  TView* treeControl = toolControl->ResolveControlByTag(0x74726565); // "tree"
  if (treeControl != nullptr) {
    treeControl->SetEnabled(enabledState, 1);
  }
  return 0;
}
