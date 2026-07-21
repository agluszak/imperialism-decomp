#include "game/TMapUberPicture.h"

#include "game/quickdraw_regions.h"
#include "game/TAmbitApplication.h"
#include "game/TAnimator.h"
#include "game/TArmyMgr.h"
#include "game/TCivMgr.h"
#include "game/TMapDialog.h"
#include "game/TMapMgr.h"
#include "game/TMiniMapView.h"
#include "game/TAssetMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TOcean.h"
#include "game/TOceanDialog.h"
#include "game/TSimMgr.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

// 0x597020 -- composes and dispatches the turn-summary message (scenario tag line +
// multiplayer game-name line + build version), defined below.
void ComposeAndDispatchTurnSummaryLocalizedMessage();

// SYNTHETIC: IMPERIALISM 0x00596900
// TMapUberPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005969c0
// TMapUberPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapUberPicture, TMapUberUberPicture)

// FUNCTION: IMPERIALISM 0x005969e0
TMapUberPicture::TMapUberPicture()
    : invalidationFlag94(1), activeUnitCategoryIndex96(3), orderEntryContext98(nullptr),
      unresolvedZero9C(0), unresolvedZeroA0(0), goodGoldTagControlA4(nullptr),
      miniMapViewC0(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x00596a30
// TMapUberPicture::`scalar deleting destructor'
TMapUberPicture::~TMapUberPicture() {}

// FUNCTION: IMPERIALISM 0x00596a80
void TMapUberPicture::DoPostCreate(int arg) {
  TOffLimitsPicture::DoPostCreate(arg);

  static_cast<TAmbitApplication*>(g_pGlobalUiRootController)->edgeScrollTarget48 = this;

  subview2A8 = static_cast<TMapDialog*>(ResolveControlByTag(kControlTagGold));
  subview2A8->AssertValid();

  TOceanDialog* alternateMapDialog =
      static_cast<TOceanDialog*>(ResolveControlByTag(0x444f4f47)); // 'DOOG'
  if (alternateMapDialog != nullptr) {
    goodGoldTagControlA4 = alternateMapDialog;
    alternateMapDialog->AssertValid();
  }

  subviewAc = subview2A8;
  categoryPages[0] = ResolveControlByTag(0x75636976); // 'uciv'
  categoryPages[1] = ResolveControlByTag(0x7561726d); // 'uarm'
  categoryPages[2] = ResolveControlByTag(0x756e6176); // 'unav'
  categoryPages[3] = nullptr;

  RECT mapBounds;
  subview2A8->QueryBounds(&mapBounds);
  RECT mapRegionBounds = mapBounds;
  RgnHandle mapRegion = NewRgn();
  RectRgn(mapRegion, &mapRegionBounds);
  ForwardCopyRgn(mapRegion);
  DisposeRgn(mapRegion);

  g_pUiRuntimeContext->mapUberPictureF0 = this;
  g_pUiAnimator->mapUberPicture2c = this;
  g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(nullptr);
  g_pActiveMapOrderContext->RefreshMapActionContextNationOverlaysAndOrderRanks();

  unsigned char multiplayerSessionActive = g_pSimMgr->field44 != 0;
  if (multiplayerSessionActive != 0) {
    TView* sendControl = ResolveControlByTag(0x73656e64); // 'send'
    sendControl->AssertValid();
    sendControl->SetState(1, 0);
    sendControl->SetEnabled(1, 0);
    LoadUiStringByGroupAndIndexToControlObject(0x2742, 0xe, sendControl);
  }
}

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
    g_pUiAnimator->mapUberPicture2c = 0;
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
      this->EnterMapInteractionOverlayMode(nullptr);
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

// FUNCTION: IMPERIALISM 0x00597020
void ComposeAndDispatchTurnSummaryLocalizedMessage() {
  CString summary;
  CString tempMsg;

  if (strcmp(g_szEmptyString, static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText1c)) != 0) {
    g_pSimMgr->GetString(0x273f, 1, &tempMsg);
    scanBracketExpressions(g_pSimMgr, &summary, static_cast<LPCSTR>(tempMsg),
                           static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText1c));
  }

  if (g_pSimMgr->field44 != 0) {
    CString sectionMsg;
    g_pSimMgr->GetString(0x2742, 0x24, &tempMsg);
    scanBracketExpressions(g_pSimMgr, &sectionMsg, static_cast<LPCSTR>(tempMsg),
                           static_cast<LPCSTR>(g_pGameFlowState->gameNameString));
    summary += sectionMsg;
  }

  CString versionText;
  g_pUiViewManager->FormatVersionStringFromVersionResource(&versionText);

  if (strcmp(g_szEmptyString, static_cast<LPCSTR>(versionText)) != 0) {
    if (strcmp(g_szEmptyString, static_cast<LPCSTR>(summary)) != 0) {
      summary = summary + s_szDoubleNewline_00699438;
    }
    summary += versionText;
  }

  if (strcmp(g_szEmptyString, static_cast<LPCSTR>(summary)) != 0) {
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
        summary, &g_cstrMapModeMessageStore, 0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00597340
void TMapUberPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    bool ctrlHeld = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    unsigned int tag = sourceHandler->controlTag;
    if (ctrlHeld && (tag == kControlTagZmIn || tag == kControlTagZmOt)) {
      ComposeAndDispatchTurnSummaryLocalizedMessage();
      return;
    }
    if (tag == kControlTagZmOt) {
      CommitPendingUiModeChangeAndRefreshViews(static_cast<TView*>(sourceHandler));
      return;
    } else if (tag == kControlTagZmIn) {
      EnterMapInteractionOverlayMode(static_cast<TView*>(sourceHandler));
      return;
    } else if (tag == kControlTagCanc) {
      if (g_pSimMgr->field44 != 0) {
        CString msg;
        g_pSimMgr->GetString(0x2742, 0x25, &msg);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            msg, &g_cstrMapModeMessageStore, 0, 0);
      } else {
        ReinitializeGameFlowAndPostTurnEventCode(0x5dd);
      }
      return;
    } else if (tag == kControlTagSend) {
      if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
        if (g_pGameFlowState->fieldF4 != 0) {
          g_pSimMgr->SetGlobalTurnStateCodeIfAllowed(0x72);
        }
        // else: falls through with no further action in the original.
        return;
      }
      g_pGameFlowState->RefreshPoseMessageDialogNationSelectionControls(-1);
      return;
    }
  } else if (commandId == 0xc) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= kControlTagAgr0 && tag <= kControlTagAgr2) {
      TTaskForce* taskForce = g_pActiveMapOrderContext->selectedTaskForce14;
      if (taskForce != nullptr) {
        taskForce->ResetOrderTypeAndStrengthDword(static_cast<int>(tag - kControlTagAgr0));
      }
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00597600
void TMapUberPicture::vmethod_0017(int param) {}

// FUNCTION: IMPERIALISM 0x00597770
void TMapUberPicture::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x005977a0
void TMapUberPicture::AutoScrollByEdgeMask(short edgeMask) {
  if (invalidationFlag94 != 0) {
    subview2A8->UpdateMapInteractionPreviewParityAndRenderTransientSprites(edgeMask);
  } else {
    goodGoldTagControlA4->ApplyDirectionalNudgeAndRefreshDisplay(
        static_cast<unsigned char>(edgeMask));
  }
  if (miniMapViewC0 != nullptr) {
    miniMapViewC0->RefreshControl();
  }
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
  // SetAvailableAndSelectedShipCounts -- thiscall on the resolved
  // TShipFractionCluster) still depends on TTaskForce fields and child methods not yet
  // recovered beyond what TOcean.cpp established, so the chain is left as a documented
  // gap rather than using fake calling conventions; the real control-resolution/
  // AssertValid structure and quota-field reads are reproduced.
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
  this->subviewAc->OrphanRetStub_005966c0(entryIndex);
  if (this->invalidationFlag94 == 0) {
    this->subview2A8->ReleaseTileMarkerForTile(entryIndex);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00598910
undefined TMapUberPicture::OrphanCallChain_C2_I11_00598910(undefined4 param_1) {
  this->PrepareForDrawing();
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
  this->subviewAc->UpdateMapDialogTileRowColumnMarkerAndInvalidate(param);
  if (this->miniMapViewC0 != nullptr) {
    this->miniMapViewC0->RefreshControl();
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
  this->subviewAc->OrphanCallChain_C6_I29_00596700(entryIndex);
  return 0;
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
  EnterMapInteractionOverlayMode(nullptr);
  SetMapInteractionMode(0);
}

// FUNCTION: IMPERIALISM 0x00599a50
void TMapUberPicture::EnterMapInteractionOverlayMode(TView* controlOverride) {
  if (this->invalidationFlag94 != 0) {
    return;
  }
  TView* zoomControl =
      (controlOverride != nullptr) ? controlOverride : this->ResolveControlByTag(0x5a6d496e);
  zoomControl->AssertValid();
  if (zoomControl != nullptr) {
    zoomControl->controlTag = 0x5a6d4f74; // "ZmOt" ("Zoom Out")
  }
  this->invalidationFlag94 = 1;

  int selectedTile = goodGoldTagControlA4->ComputeWrappedTileIndexFromObjectOffset7C7E();
  subview2A8->UpdateMapDialogTileRowColumnMarkerAndInvalidate(selectedTile);

  this->goodGoldTagControlA4->CaptureLayoutF0(g_MapUberModeLayoutScratch_006a45e8, 0);
  this->subview2A8->CaptureLayoutF0(g_MapUberModeSecondaryLayoutScratch_006a45b8, 1);
  this->subviewAc = this->subview2A8;

  if (this->miniMapViewC0 != nullptr) {
    this->miniMapViewC0->markerBoxWidth98 = g_defaultMarkerBoxWidth_006a460c;
    this->miniMapViewC0->markerBoxHeight9c = 8;
    this->miniMapViewC0->markerBoxX90 =
        this->miniMapViewC0->frameWidth34 / 2 - this->miniMapViewC0->markerBoxWidth98 - 2;
    this->miniMapViewC0->markerBoxY94 =
        this->miniMapViewC0->frameHeight38 / 2 - this->miniMapViewC0->markerBoxHeight9c - 2;
    this->miniMapViewC0->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00599b90
void TMapUberPicture::CommitPendingUiModeChangeAndRefreshViews(TView* controlOverride) {
  if (invalidationFlag94 != 0) {
    if (g_pUiAnimator != nullptr) {
      // The original also calls g_pUiAnimator->registryList24's own vtable slot 0x54 here
      // (CallObjectOffset24Vslot54IfPresent) -- TList's real slot at that byte offset is
      // unresolved, so left unmodeled.
    }
    TView* zoomControl =
        (controlOverride != nullptr) ? controlOverride : ResolveControlByTag(kControlTagZmOt);
    zoomControl->AssertValid();
    if (zoomControl != nullptr) {
      zoomControl->controlTag = kControlTagZmIn;
    }
    invalidationFlag94 = 0;
    // The original also dispatches subview2A8/goodGoldTagControlA4's own vtable slots
    // 0x288/0x1d8/0xf0 here (beyond either class's currently-declared extent), then writes
    // goodGoldTagControlA4's raw pointer value into subviewAc -- but goodGoldTagControlA4
    // is TOceanDialog* (TWorldView-derived) while subviewAc is declared TMapDialog*, an
    // unrelated type per the existing class hierarchy, so that assignment is left
    // unmodeled pending resolution of the mismatch, along with refreshing miniMapViewC0's
    // rect cache.
  }
}

// FUNCTION: IMPERIALISM 0x00599cf0
void TMapUberPicture::DisplayMiniMap() {
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
  this->miniMapViewC0 = miniMap;

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
    this->miniMapViewC0->markerBoxWidth98 = 0x20;
    this->miniMapViewC0->markerBoxHeight9c = 0x1c;
    this->miniMapViewC0->markerBoxX90 =
        this->miniMapViewC0->frameWidth34 / 2 - this->miniMapViewC0->markerBoxWidth98 - 2;
    this->miniMapViewC0->markerBoxY94 =
        this->miniMapViewC0->frameHeight38 / 2 - this->miniMapViewC0->markerBoxHeight9c - 2;
    this->miniMapViewC0->RefreshControl();
  }

  this->SetTradeToolSubcontrolEnabledStateByFlag(0);
}

// FUNCTION: IMPERIALISM 0x00599fa0
void TMapUberPicture::InvalidateMiniMap() {
  // The original null-checks the receiver: call sites invoke this on a possibly-null
  // ownerContext without guarding it.
  if (this != 0 && miniMapViewC0 != 0) {
    miniMapViewC0->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00599fd0
void TMapUberPicture::RemoveMiniMap() {
  TView* toolControl = ResolveControlByTag(0x746f6f6c); // 'tool'
  if (toolControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0xa97);
  }

  RECT mapBounds;
  subviewAc->QueryBounds(&mapBounds);
  RgnHandle mapRegion = NewRgn();
  RectRgn(mapRegion, &mapBounds);
  ForwardCopyRgn(mapRegion);
  DisposeRgn(mapRegion);

  RECT toolRect;
  toolRect.left = toolControl->ownerLocalX + 5;
  toolRect.top = toolControl->ownerLocalY + 0x37;
  toolRect.right = toolControl->ownerLocalX + 0x76;
  toolRect.bottom = toolControl->ownerLocalY + 0x78;
  InvalidateCityDialogRectRegion(&toolRect, 1);

  if (miniMapViewC0 != nullptr) {
    miniMapViewC0->Free();
  }
  miniMapViewC0 = nullptr;

  TPicture* miniMapButton =
      static_cast<TPicture*>(toolControl->ResolveControlByTag(0x696e666f)); // 'info'
  if (miniMapButton == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0xab4);
  }
  miniMapButton->SetPictureResourceIdAndRefresh(0x41a, true);
  miniMapButton->controlTag = 0x6d6d6170; // 'mmap'
  SetTradeToolSubcontrolEnabledStateByFlag(true);
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
