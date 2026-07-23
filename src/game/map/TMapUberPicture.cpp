#include "game/map/TMapUberPicture.h"

#include "game/gfx/quickdraw_regions.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/app/TAnimator.h"
#include "game/military/TArmyMgr.h"
#include "game/navy/TAdmiral.h"
#include "game/city_ui/TCivMgr.h"
#include "game/military/TCivUnit.h"
#include "game/map_ui/TMapDialog.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMiniMapView.h"
#include "game/assets/TAssetMgr.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/navy_ui/TNavyToolbarCluster.h"
#include "game/navy/TOcean.h"
#include "game/navy_ui/TOceanDialog.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/navy_ui/TShipFractionCluster.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_widgets/TToolBarCluster.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_core/TNumberText.h"
#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/navy_order.h"
#include "game/navy_ui/TNavyRoster.h"
#include "game/ui_control_tags.h"
#include "game/gfx/ui_invalidation_guard.h"
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
      unresolvedZero9C(0), navyRosterA0(0), goodGoldTagControlA4(nullptr), miniMapViewC0(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x00596a30
// TMapUberPicture::`scalar deleting destructor'
TMapUberPicture::~TMapUberPicture() {}

// FUNCTION: IMPERIALISM 0x00596a80
void TMapUberPicture::DoPostCreate(int arg) {
  TOffLimitsPicture::DoPostCreate(arg);

  g_pGlobalUiRootController->edgeScrollTarget48 = this;

  subview2A8 = static_cast<TMapDialog*>(ResolveControlByTag(kControlTagDialog));
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

  CRect mapBounds;
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
  g_pGlobalUiRootController->edgeScrollTarget48 = 0;
  g_pGlobalUiRootController->cursorRegionInvalid = FALSE;
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

    // Mac MapView.rsrc:2013 identifies 'tbr1' as TToolBarCluster and its 'seas' child as
    // TDropShadowText. Windows reuses that child as 'forc' while army mode is active.
    TToolBarCluster* toolbar =
        static_cast<TToolBarCluster*>(GetWindow()->ResolveControlByTag(0x74627231)); // 'tbr1'
    if (toolbar != nullptr) {
      if (previousMode == 1) {
        TView* caption = toolbar->ResolveControlByTag(0x666f7263); // 'forc'
        caption->AssertValid();
        caption->controlTag = 0x73656173; // 'seas'

        CString seasonCaption;
        CString yearCaption;
        g_pSimMgr->GetString(0x2730, 0x12, &seasonCaption);
        g_pSimMgr->GetString(0x2730, 8, &yearCaption);
        CString hoverHelp = seasonCaption + g_szListSeparator_00695760 + yearCaption;
        SetControlHoverHelpTextAltEntry(hoverHelp, caption);
      } else if (nMode == 1) {
        CString hoverHelp;
        TView* caption = toolbar->ResolveControlByTag(0x73656173); // 'seas'
        caption->AssertValid();
        caption->controlTag = 0x666f7263; // 'forc'
        g_pSimMgr->GetString(0x2732, 0x11, &hoverHelp);
        SetControlHoverHelpTextAltEntry(hoverHelp, caption);
      }

      toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetActiveNationId());
    }

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
void TMapUberPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
        ReinitializeGameFlowAndPostTurnEventCode(kTurnEventRandomGameSetup);
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
        taskForce->SetAggression(static_cast<int>(tag - kControlTagAgr0));
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00597600
void TMapUberPicture::DoMenuCommand(int command) {
  if (command != 0x406) {
    return;
  }

  switch (activeUnitCategoryIndex96) {
  case 0:
    if (g_pSelectedCivilianOrderState->selectedEntry != 0) {
      CenterOn(g_pSelectedCivilianOrderState->selectedEntry->tileIndex06);
    }
    return;

  case 1:
    if (g_pMapContextActionManager->pendingMapActionIndex != -1) {
      CenterOn(g_pGlobalMapState->cityScoreTable[g_pMapContextActionManager->pendingMapActionIndex]
                   .cityTileIndex04);
    }
    return;

  case 2:
    if (orderEntryContext98 != 0) {
      CenterOn(orderEntryContext98->tileOrTerrainId0c);
    }
    return;

  case 3:
    CenterOn(
        g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(g_pSimMgr->GetActiveNationId()));
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00597770
void TMapUberPicture::DoKeyEvent(TToolboxEvent* event) {
  if (subviewAc != 0) {
    subviewAc->DoKeyEvent(event);
  }
}

// FUNCTION: IMPERIALISM 0x005977a0
void TMapUberPicture::Scroll(MapScrollEdgeMaskStorage edgeMask) {
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
  ResetMapActionContextActivityAndNationFlags();

  if (pMapOrderEntry == nullptr) {
    for (int i = 0; i < 4; ++i) {
      TShipFractionCluster* shipClass =
          static_cast<TShipFractionCluster*>(ResolveControlByTag(0x636c7330 + i)); // 'cls0'..'cls3'
      shipClass->AssertValid();
      shipClass->SetAvailableAndSelectedShipCounts(0, -1);
    }
    return;
  }

  TZone* context = pMapOrderEntry->location;
  context->ExpandTaskForceTraversalDepthAndMarkDeferredNodes(pMapOrderEntry->GetWorstSpeed(), 1);
  CenterOn(static_cast<short>(context->tileOrTerrainId0c));

  for (int i = 0; i < 4; ++i) {
    TShipFractionCluster* shipClass =
        static_cast<TShipFractionCluster*>(ResolveControlByTag(0x636c7330 + i)); // 'cls0'..'cls3'
    shipClass->AssertValid();
    shipClass->SetAvailableAndSelectedShipCounts(
        pMapOrderEntry->shipCountsByToolbarSlot[i],
        pMapOrderEntry->GetSelected(static_cast<short>(i)));
  }

  TNavyToolbarCluster* navyToolbar =
      static_cast<TNavyToolbarCluster*>(ResolveControlByTag(0x756e6176)); // 'unav'
  navyToolbar->AssertValid();
  navyToolbar->SetSelectedChildTagAndRefresh(kControlTagAgr0 + pMapOrderEntry->aggression);
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
bool TMapUberPicture::HasActiveMapInteractionSelection() {
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

// FUNCTION: IMPERIALISM 0x00597a80
void TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick() {
  unsigned char modeCursor = static_cast<unsigned char>(activeUnitCategoryIndex96);
  unsigned char visitedModes = 0;
  char selectionResolved = 0;
  unsigned char previousMode = modeCursor;

  short activeNation = g_pSimMgr->GetActiveNationId();
  if (!g_pSimMgr->IsNationSlotEligibleForEventProcessing(activeNation)) {
    visitedModes = 7;
  }

  while (visitedModes != 7 && selectionResolved == 0) {
    switch (modeCursor) {
    case 0: {
      if (previousMode != 0) {
        g_pSelectedCivilianOrderState->ClearCivilianSelectionHighlightsForNation(
            g_pSimMgr->GetActiveNationId());
        visitedModes |= 1;
      }

      TCivUnit* civilian = g_pSelectedCivilianOrderState->SelectFirstAvailableCivilianForNation(
          g_pSimMgr->GetActiveNationId());
      if (civilian != nullptr) {
        selectionResolved = 1;
        if (activeUnitCategoryIndex96 != 0) {
          EnterMapInteractionOverlayMode(nullptr);
          SetMapInteractionMode(0);
        }
        g_pSelectedCivilianOrderState->SetActiveCivilianSelection(civilian, 1);
        CenterOn(civilian->tileIndex06);
        ForceRedraw();
      } else {
        modeCursor = 1;
        previousMode = 0;
        if (activeUnitCategoryIndex96 != 0) {
          visitedModes |= 1;
        }
      }
      break;
    }

    case 1: {
      if (previousMode != 1) {
        g_pMapContextActionManager->ClearProvinceSelectionHighlightsForNation(
            g_pSimMgr->GetActiveNationId());
        visitedModes |= 2;
      }

      short province = g_pMapContextActionManager->FindNextSelectableProvinceForNation(
          g_pSimMgr->GetActiveNationId());
      if (province != -1) {
        if (activeUnitCategoryIndex96 != 1) {
          SetMapInteractionMode(1);
        }
        g_pMapContextActionManager->SetActiveProvinceSelection(province);
        CenterOn(g_pGlobalMapState->cityScoreTable[province].cityTileIndex04);
        selectionResolved = 1;
      } else {
        modeCursor = 2;
        previousMode = 1;
        if (activeUnitCategoryIndex96 != 1) {
          visitedModes |= 2;
        }
      }
      break;
    }

    case 2:
      if (TrySelectNextValidMapOrderEntry(0)) {
        selectionResolved = 1;
      } else {
        modeCursor = 0;
        orderEntryContext98 = nullptr;
        previousMode = 2;
        visitedModes |= 4;
      }
      break;

    case 3:
      modeCursor = 0;
      break;
    }
  }

  // A completed traversal wraps the navy chain once: the failed navy scan cleared the
  // current cursor, so this second scan starts at g_pMapActionContextListHead.
  if (visitedModes == 7 && selectionResolved == 0) {
    selectionResolved = TrySelectNextValidMapOrderEntry(0) ? 1 : 0;
  }

  if (selectionResolved != 0) {
    return;
  }

  switch (activeUnitCategoryIndex96) {
  case 0:
    g_pSelectedCivilianOrderState->selectedEntry = nullptr;
    break;
  case 1:
    g_pMapContextActionManager->SetActiveProvinceSelection(-1);
    SetMapInteractionMode(3);
    return;
  case 2:
    SetMapInteractionMode(2);
    InvalidateMapRegionForEntryIfUiPassive(orderEntryContext98);
    orderEntryContext98 = nullptr;
    InvalidateMapRegionForEntryIfUiPassive(nullptr);
    RefreshMapOrderEntryPanel(nullptr);
    SetMapInteractionMode(3);
    return;
  }
  SetMapInteractionMode(3);
}

// FUNCTION: IMPERIALISM 0x00597f80
void TMapUberPicture::InspectTaskForceDialog(TTaskForce* taskForce) {
  TextStyle titleStyle;
  TextStyle bodyStyle;
  TextStyle detailStyle;
  TextStyle attributionStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 14, 0x2b67, 1);
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 12, 0x2b67);
  InitializeUiTextStyleDescriptor(&detailStyle, 0, 10, 0x2b67, 3);
  InitializeUiTextStyleDescriptor(&attributionStyle, 2, 10, 0x2b67, 3);

  // Mac resource oracle: MapView.rsrc:9474, event 0x2502, "Friendly Fleet Report".
  TWindow* dialog = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventFriendlyFleetReport));
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
  taskForce->location->AssignZoneDisplayNameToOutputRef(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6164616d)); // adam
  control->AssertValid();
  taskForce->GetAuthority(&value);
  g_pSimMgr->GetString(0x2762, 0, &reportTemplate);
  scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                         static_cast<LPCSTR>(value));
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x77686f6d)); // whom
  control->AssertValid();
  taskForce->GetCompositionDescription(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6f726473)); // ords
  control->AssertValid();
  switch (taskForce->shipOrders) {
  case 1:
    taskForce->target.asZone->AssignZoneDisplayNameToOutputRef(&value);
    g_pSimMgr->GetString(0x2762, 0xb, &reportTemplate);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  case 3:
    taskForce->location->AssignZoneDisplayNameToOutputRef(&value);
    g_pSimMgr->GetString(0x2762, 1, &reportTemplate);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  case 5:
    g_pSimMgr->GetString(0x2762, 2, &text);
    break;
  case 6:
    taskForce->target.asZone->AssignZoneDisplayNameToOutputRef(&value);
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0x39);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  default:
    g_pSimMgr->GetString(0x2762, 3, &text);
    break;
  }
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6167726f)); // agro
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(taskForce->aggression + 4), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(attributionStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7469746c)); // titl
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 7, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(titleStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616231)); // lab1
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 8, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616232)); // lab2
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 9, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616233)); // lab3
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 0xa, &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(bodyStyle, 0);

  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }
  int result = dialog->PoseModally();
  dialog->Close();
  dialog->Free();

  if (result == 0x63616e63) { // 'canc'
    TZone* previousContext = taskForce->location;
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

// FUNCTION: IMPERIALISM 0x00598840
void TMapUberPicture::InvalidateMapRegionForEntryIfUiPassive(TZone* zone) {
  if (invalidationFlag94 == 0) {
    goodGoldTagControlA4->InvalidateZone(zone);
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
  this->subviewAc->RefreshMapTile(tileIndex);
  if (this->invalidationFlag94 == 0) {
    this->subview2A8->ReleaseTileMarkerForTile(tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x00598910
void TMapUberPicture::PrepareAndRenderMapOverlayMode(unsigned char overlayMode) {
  this->PrepareForDrawing();
  subviewAc->SetMapOverlayModeAndRenderPreview(overlayMode);
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
  this->subviewAc->NoticeTile(tileIndex);
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

  TWindow* dialog = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNavyMaker));
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
  TextStyle titleStyle;
  TextStyle bodyStyle;
  TextStyle detailStyle;
  TextStyle attributionStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 14, 0x2b67, 1);
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 12, 0x2b67);
  InitializeUiTextStyleDescriptor(&detailStyle, 0, 10, 0x2b67, 3);
  InitializeUiTextStyleDescriptor(&attributionStyle, 2, 10, 0x2b67, 3);

  // Mac resource oracle: MapView.rsrc:9475, event 0x2503, "Enemy Fleet Report".
  TWindow* dialog = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventEnemyFleetReport));
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
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7a6f6e65)); // zone
  control->AssertValid();
  zone->AssignZoneDisplayNameToOutputRef(&text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6164616d)); // adam
  control->AssertValid();
  if (cachedTaskForce != 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0x34);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(cachedTaskForce->target.asProvince->cityNameA4));
  } else {
    zone->BuildNavalIntelligenceSourceDescription(&text, g_pSimMgr->GetActiveNationId());
  }
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(attributionStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x73686970)); // ship
  control->AssertValid();
  if (cachedTaskForce != 0) {
    cachedTaskForce->GetCompositionDescription(&text);
  } else {
    TAdmiral* observer = zone->FindReportingAdmiralForNation(g_pSimMgr->GetActiveNationId());
    observer->GetFleetReport(&text, zone, nation);
  }
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  int stringIndex = cachedTaskForce != 0 ? 0x2e : 0x29;
  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7469746c)); // titl
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(titleStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616231)); // lab1
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616232)); // lab2
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616233)); // lab3
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x6c616234)); // lab4
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex), &text);
  control->SetTextAndMaybeRefresh(&text, 0);
  control->InstallTextStyle(attributionStyle, 0);

  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }
  dialog->PoseModally();
  dialog->Close();
  dialog->Free();
}

// FUNCTION: IMPERIALISM 0x00599770
void TMapUberPicture::SelectNextValidMapOrderEntryFromCursor(char includeCurrent) {
  if (activeUnitCategoryIndex96 != 2) {
    return;
  }

  g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(nullptr);
  TZone* candidate = orderEntryContext98;
  if (candidate != nullptr && includeCurrent == 0) {
    candidate = candidate->prev18;
  }
  if (candidate == nullptr) {
    candidate = g_pMapActionContextListHead;
  }

  while (candidate != nullptr) {
    if (candidate->CanDisplayMapOrderEntryInCurrentContext(-1, 0)) {
      SetMapInteractionMode(2);
      InvalidateMapRegionForEntryIfUiPassive(orderEntryContext98);
      orderEntryContext98 = candidate;
      InvalidateMapRegionForEntryIfUiPassive(candidate);
      TTaskForce* taskForce =
          g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(candidate);
      RefreshMapOrderEntryPanel(taskForce);
      return;
    }
    candidate = candidate->prev18;
  }
  orderEntryContext98 = nullptr;
}

// FUNCTION: IMPERIALISM 0x005998a0
bool TMapUberPicture::TrySelectNextValidMapOrderEntry(char includeCurrent) {
  g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(nullptr);

  TZone* candidate = orderEntryContext98;
  if (candidate != nullptr && includeCurrent == 0) {
    candidate = candidate->prev18;
  }
  if (candidate == nullptr) {
    candidate = g_pMapActionContextListHead;
  }

  while (candidate != nullptr) {
    if (candidate->CanDisplayMapOrderEntryInCurrentContext(-1, 0)) {
      SetMapInteractionMode(2);
      InvalidateMapRegionForEntryIfUiPassive(orderEntryContext98);
      orderEntryContext98 = candidate;
      InvalidateMapRegionForEntryIfUiPassive(candidate);
      TTaskForce* taskForce =
          g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(candidate);
      RefreshMapOrderEntryPanel(taskForce);
      return true;
    }
    candidate = candidate->prev18;
  }

  orderEntryContext98 = nullptr;
  return false;
}

// FUNCTION: IMPERIALISM 0x005999f0
void TMapUberPicture::ResetMapInteractionToCivilianMode() {
  EnterMapInteractionOverlayMode(nullptr);
  SetMapInteractionMode(0);
}

// FUNCTION: IMPERIALISM 0x00599a20
void TMapUberPicture::UpdateRoster() {
  if (navyRosterA0 != 0) {
    navyRosterA0->ShowPage(navyRosterA0->currentPage);
  }
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
    g_pUiAnimator->FreeUiTransientRegistryPayloads();
    TView* zoomControl =
        (controlOverride != nullptr) ? controlOverride : ResolveControlByTag(kControlTagZmOt);
    zoomControl->AssertValid();
    if (zoomControl != nullptr) {
      zoomControl->controlTag = kControlTagZmIn;
    }
    invalidationFlag94 = 0;
    goodGoldTagControlA4->CenterOn(subview2A8->GetCenterTile());
    subview2A8->CaptureLayoutF0(g_MapUberModeLayoutScratch_006a45e8, 0);
    goodGoldTagControlA4->CaptureLayoutF0(g_MapUberModeSecondaryLayoutScratch_006a45b8, 1);
    TMiniMapView* miniMap = miniMapViewC0;
    subviewAc = goodGoldTagControlA4;

    if (miniMap != nullptr) {
      miniMap->markerBoxWidth98 = 0x20;
      miniMap->markerBoxHeight9c = 0x1c;
      miniMap->markerBoxX90 = miniMap->frameWidth34 / 2 - miniMap->markerBoxWidth98 - 2;
      miniMap->markerBoxY94 = miniMap->frameHeight38 / 2 - miniMap->markerBoxHeight9c - 2;
      miniMap->RefreshControl();
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

  CRect mapBounds;
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
void TMapUberPicture::SetTradeToolSubcontrolEnabledStateByFlag(bool enabledState) {
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
}
