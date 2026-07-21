#include "game/TMapUberPicture.h"

#include "game/quickdraw_regions.h"
#include "game/TAmbitApplication.h"
#include "game/TAnimator.h"
#include "game/TArmyMgr.h"
#include "game/TAdmiral.h"
#include "game/TCivMgr.h"
#include "game/TMapDialog.h"
#include "game/TMapMgr.h"
#include "game/TMiniMapView.h"
#include "game/TAssetMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TOcean.h"
#include "game/TOceanDialog.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TNumberText.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/navy_order.h"
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

  unsigned char multiplayerSessionActive = g_pSimMgr->multiplayerSessionRole != 0;
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

  if (g_pSimMgr->multiplayerSessionRole != 0) {
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
    g_pUiRuntimeContext->ModalMessage(summary, g_ptMapModeModalMessage, 0, 0);
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
      if (g_pSimMgr->multiplayerSessionRole != 0) {
        CString msg;
        g_pSimMgr->GetString(0x2742, 0x25, &msg);
        g_pUiRuntimeContext->ModalMessage(msg, g_ptMapModeModalMessage, 0, 0);
      } else {
        ReinitializeGameFlowAndPostTurnEventCode(0x5dd);
      }
      return;
    } else if (tag == kControlTagSend) {
      if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
        if (g_pGameFlowState->fieldF4 != 0) {
          g_pSimMgr->EnterOptionalPhase(0x72);
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
  this->CenterOn(commandCode);

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
  goodGoldTagControlA4->InvalidateZone(orderEntryContext98);
  this->orderEntryContext98 = pMapOrderContextZone;
  goodGoldTagControlA4->InvalidateZone(pMapOrderContextZone);
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

// FUNCTION: IMPERIALISM 0x00597f80
void TMapUberPicture::InspectTaskForceDialog(TTaskForce* taskForce) {
  TUiTextStyleDescriptor titleStyle;
  TUiTextStyleDescriptor bodyStyle;
  TUiTextStyleDescriptor detailStyle;
  TUiTextStyleDescriptor attributionStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 14, 0x2b67, 1);
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 12, 0x2b67);
  InitializeUiTextStyleDescriptor(&detailStyle, 0, 10, 0x2b67, 3);
  InitializeUiTextStyleDescriptor(&attributionStyle, 2, 10, 0x2b67, 3);

  // Mac resource oracle: MapView.rsrc:9474, event 0x2502, "Friendly Fleet Report".
  TWindow* dialog =
      static_cast<TWindow*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2502));
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0x728);
  }
  dialog->SetModality(1);

  CString text;
  CString value;
  CString reportTemplate;
  TStaticText* control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7a6f6e65)); // zone
  control->AssertValid();
  taskForce->contextAnchor->AssignZoneDisplayNameToOutputRef(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6164616d)); // adam
  control->AssertValid();
  taskForce->GetAuthority(&value);
  g_pSimMgr->GetString(0x2762, 0, &reportTemplate);
  scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                         static_cast<LPCSTR>(value));
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x77686f6d)); // whom
  control->AssertValid();
  taskForce->GetCompositionDescription(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6f726473)); // ords
  control->AssertValid();
  switch (taskForce->attachment) {
  case 1:
    taskForce->owner.asZone->AssignZoneDisplayNameToOutputRef(&value);
    g_pSimMgr->GetString(0x2762, 0xb, &reportTemplate);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  case 3:
    taskForce->contextAnchor->AssignZoneDisplayNameToOutputRef(&value);
    g_pSimMgr->GetString(0x2762, 1, &reportTemplate);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  case 5:
    g_pSimMgr->GetString(0x2762, 2, &text);
    break;
  case 6:
    taskForce->owner.asZone->AssignZoneDisplayNameToOutputRef(&value);
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0x39);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  default:
    g_pSimMgr->GetString(0x2762, 3, &text);
    break;
  }
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6167726f)); // agro
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(taskForce->order_type + 4), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&attributionStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7469746c)); // titl
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 7, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&titleStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616231)); // lab1
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 8, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616232)); // lab2
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 9, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616233)); // lab3
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 0xa, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&bodyStyle, 0);

  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }
  int result = dialog->PoseModally();
  dialog->Close();
  dialog->Free();

  if (result == 0x63616e63) { // 'canc'
    TZone* previousContext = taskForce->contextAnchor;
    taskForce->CancelOrders(0);
    SetMapInteractionMode(2);
    goodGoldTagControlA4->InvalidateZone(orderEntryContext98);
    orderEntryContext98 = previousContext;
    goodGoldTagControlA4->InvalidateZone(previousContext);
    TTaskForce* refreshed =
        previousContext != 0
            ? g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(
                  previousContext)
            : 0;
    RefreshMapOrderEntryPanel(refreshed);
  }
}

// FUNCTION: IMPERIALISM 0x00598870
void TMapUberPicture::InvalidateTile(short tileIndex) {
  if (invalidationFlag94 != 0) {
    subview2A8->InvalidateTile(tileIndex);
  } else {
    goodGoldTagControlA4->InvalidateTile(tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005988c0
void TMapUberPicture::RedrawTile(short tileIndex) {
  this->subviewAc->OrphanRetStub_005966c0(tileIndex);
  if (this->invalidationFlag94 == 0) {
    this->subview2A8->ReleaseTileMarkerForTile(tileIndex);
  }
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
void TMapUberPicture::InvalidateMap() {
  if (invalidationFlag94 != 0) {
    subview2A8->RefreshControl();
  } else {
    goodGoldTagControlA4->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00598990
void TMapUberPicture::CenterOn(int tileIndex) {
  this->subviewAc->CenterOn(tileIndex);
  if (this->miniMapViewC0 != nullptr) {
    this->miniMapViewC0->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005989d0
void TMapUberPicture::SetUpperLeft(int tileX, int tileY) {
  this->subviewAc->SetMapViewCellCoordinates(tileX, tileY);
  if (this->miniMapViewC0 != nullptr) {
    this->miniMapViewC0->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00598a20
void TMapUberPicture::NoticeTile(int tileIndex) {
  this->subviewAc->OrphanCallChain_C6_I29_00596700(tileIndex);
}

// Windows uses the Mac MapView.rsrc:9462 "Navy Maker II" tree for this dialog.
// The resource exposes one 'num?' control per ship type that is available in the
// current ruleset; absent controls are intentionally skipped by both versions.
// FUNCTION: IMPERIALISM 0x00598e10
void TMapUberPicture::RunNavyPrimaryOrderCreationDialogAndApplyResults(TZone* portZone) {
  if (portZone == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0x8bf);
  }

  RGBQUAD highlightColor = {0xff, 0xff, 0xff, 0};
  g_pDisplayMgr->SetHiliteColor(&highlightColor);

  TWindow* dialog =
      static_cast<TWindow*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x24f6));
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0x8cc);
  }
  dialog->SetModality(1);

  short index;
  for (index = 0; index < 29; ++index) {
    TStaticText* nameControl =
        static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6e616d61u + index)); // 'nama'
    if (nameControl != 0) {
      nameControl->SetTextFromStringResource(0x2716, static_cast<short>(index + 1), 1);
    }
  }

  dialog->PoseModally();

  TNumberText* ownerControl =
      static_cast<TNumberText*>(dialog->ResolveControlByTag(0x6f776e65u)); // 'owne'
  ownerControl->AssertValid();
  int ownerNation = ownerControl->UpdateControlCachedIntFromWindowText();

  unsigned char createdOrders = 0;
  for (index = 0; index < 14; ++index) {
    TNumberText* countControl =
        static_cast<TNumberText*>(dialog->ResolveControlByTag(0x6e756d61u + index)); // 'numa'
    if (countControl != 0) {
      short count = static_cast<short>(countControl->UpdateControlCachedIntFromWindowText());
      if (count != 0) {
        while (count > 0) {
          CreateNavyPrimaryOrderNodeAndAssignDisplayName(static_cast<short>(index), portZone,
                                                         ownerNation, 0);
          --count;
        }
        createdOrders = 1;
      }
    }
  }

  dialog->Close();
  dialog->Free();

  if (createdOrders != 0) {
    g_pActiveMapOrderContext->RefreshMapActionContextNationOverlaysAndOrderRanks();
  }

  SetMapInteractionMode(2);
  if (invalidationFlag94 == 0) {
    goodGoldTagControlA4->InvalidateZone(orderEntryContext98);
  }
  orderEntryContext98 = portZone;
  if (invalidationFlag94 == 0) {
    goodGoldTagControlA4->InvalidateZone(portZone);
  }

  if (portZone == 0) {
    RefreshMapOrderEntryPanel(0);
    return;
  }
  TTaskForce* taskForce =
      g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(portZone);
  RefreshMapOrderEntryPanel(taskForce);
}

// FUNCTION: IMPERIALISM 0x00599090
void TMapUberPicture::NavalIntelligenceDialog(TZone* zone, short nation,
                                              TTaskForce* cachedTaskForce) {
  TUiTextStyleDescriptor titleStyle;
  TUiTextStyleDescriptor bodyStyle;
  TUiTextStyleDescriptor detailStyle;
  TUiTextStyleDescriptor attributionStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 14, 0x2b67, 1);
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 12, 0x2b67);
  InitializeUiTextStyleDescriptor(&detailStyle, 0, 10, 0x2b67, 3);
  InitializeUiTextStyleDescriptor(&attributionStyle, 2, 10, 0x2b67, 3);

  // Mac resource oracle: MapView.rsrc:9475, event 0x2503, "Enemy Fleet Report".
  TWindow* dialog =
      static_cast<TWindow*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2503));
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSuperMap_0069943C, 0x923);
  }
  dialog->SetModality(1);

  CString text;
  CString reportTemplate;
  TStaticText* control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x67706565)); // gpee
  control->AssertValid();
  g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7a6f6e65)); // zone
  control->AssertValid();
  zone->AssignZoneDisplayNameToOutputRef(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6164616d)); // adam
  control->AssertValid();
  if (cachedTaskForce != 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0x34);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(cachedTaskForce->owner.asCityTarget->cityNameA4));
  } else {
    zone->BuildNavalIntelligenceSourceDescription(&text, g_pSimMgr->GetActiveNationId());
  }
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&attributionStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x73686970)); // ship
  control->AssertValid();
  if (cachedTaskForce != 0) {
    cachedTaskForce->GetCompositionDescription(&text);
  } else {
    TAdmiral* observer = zone->FindReportingAdmiralForNation(g_pSimMgr->GetActiveNationId());
    observer->GetFleetReport(&text, zone, nation);
  }
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  int stringIndex = cachedTaskForce != 0 ? 0x2e : 0x29;
  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7469746c)); // titl
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&titleStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616231)); // lab1
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616232)); // lab2
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616233)); // lab3
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616234)); // lab4
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->SetTextStyleAndMaybeRefresh(&attributionStyle, 0);

  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }
  dialog->PoseModally();
  dialog->Close();
  dialog->Free();
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
  subview2A8->CenterOn(selectedTile);

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
    short centerTile = static_cast<short>(subview2A8->GetCenterTile());
    goodGoldTagControlA4->CenterOn(centerTile);
    subview2A8->CaptureLayoutF0(g_MapUberModeLayoutScratch_006a45e8, 0);
    goodGoldTagControlA4->CaptureLayoutF0(g_MapUberModeSecondaryLayoutScratch_006a45b8, 1);
    subviewAc = goodGoldTagControlA4;

    if (miniMapViewC0 != nullptr) {
      miniMapViewC0->markerBoxWidth98 = 0x20;
      miniMapViewC0->markerBoxHeight9c = 0x1c;
      miniMapViewC0->markerBoxX90 =
          miniMapViewC0->frameWidth34 / 2 - miniMapViewC0->markerBoxWidth98 - 2;
      miniMapViewC0->markerBoxY94 =
          miniMapViewC0->frameHeight38 / 2 - miniMapViewC0->markerBoxHeight9c - 2;
      miniMapViewC0->RefreshControl();
    }
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
