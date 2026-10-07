#include "game/map/TMapUberPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"

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
#include "game/military/TMilitaryUnit.h"
#include "game/GameAssert.h"
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
#include "game/gfx/TResourceMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/navy_order.h"
#include "game/navy_ui/TNavyRoster.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

void ComposeAndDispatchTurnSummaryLocalizedMessage();

IMPLEMENT_DYNCREATE(TMapUberPicture, TMapUberUberPicture)

// FUNCTION: IMPERIALISM 0x005969e0
TMapUberPicture::TMapUberPicture()
    : invalidationFlag(1), activeUnitCategoryIndex(3), orderEntryContext(NULL), deadStore9C(0),
      navyRoster(0), goodGoldTagControl(NULL), miniMapView(NULL) {}

// FUNCTION: IMPERIALISM 0x00596a60
TMapUberPicture::~TMapUberPicture() {}

// FUNCTION: IMPERIALISM 0x00596a80
void TMapUberPicture::DoPostCreate(int arg) {
  TOffLimitsPicture::DoPostCreate(arg);

  g_pAmbitApplication->edgeScrollTarget = this;

  subview2A8 = static_cast<TMapDialog*>(FindSubView(kControlTagDialog));
  subview2A8->AssertValid();

  TOceanDialog* alternateMapDialog =
      static_cast<TOceanDialog*>(FindSubView(kControlTagDOOG)); // 'DOOG'
  if (alternateMapDialog != NULL) {
    goodGoldTagControl = alternateMapDialog;
    alternateMapDialog->AssertValid();
  }

  subview = subview2A8;
  categoryPages[0] = FindSubView(kControlTagUciv); // 'uciv'
  categoryPages[1] = FindSubView(kControlTagUarm); // 'uarm'
  categoryPages[2] = FindSubView(kControlTagUnav); // 'unav'
  categoryPages[3] = NULL;

  CRect mapBounds;
  subview2A8->GetFrame(&mapBounds);
  RECT mapRegionBounds = mapBounds;
  RgnHandle mapRegion = NewRgn();
  RectRgn(mapRegion, &mapRegionBounds);
  SetRgn(mapRegion);
  DisposeRgn(mapRegion);

  g_pViewMgr->mapUberPicture = this;
  g_pUiAnimator->mapUberPicture = this;
  g_pActiveMapOrderContext->AssembleUIForce(NULL);
  g_pActiveMapOrderContext->UpdateOccupants();

  bool multiplayerSessionActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
  if (multiplayerSessionActive) {
    TView* sendControl = FindSubView(kControlTagSend); // 'send'
    sendControl->AssertValid();
    sendControl->ViewEnable(1, 0);
    sendControl->Show(1, 0);
    LoadUiStringByGroupAndIndexToControlObject(0x2742, 0xe, sendControl);
  }
}

// FUNCTION: IMPERIALISM 0x00596c60
void TMapUberPicture::Free() {
  if (g_pViewMgr != 0) {
    g_pViewMgr->mapUberPicture = 0;
  }
  if (g_pUiAnimator != 0) {
    g_pUiAnimator->mapUberPicture = 0;
  }
  g_pAmbitApplication->edgeScrollTarget = 0;
  g_pAmbitApplication->cursorRegionInvalid = FALSE;
  TOffLimitsPicture::Free();
}

static CPoint g_MapUberModeSecondaryLayoutScratch(5, 0x1b);
static CPoint g_MapUberModeLayoutTable[4] = {CPoint(0, 0x8f), CPoint(0, 0x92), CPoint(0, 0x90)};
static CPoint g_MapUberModeLayoutScratch(-1000, -1000);

// FUNCTION: IMPERIALISM 0x00596cb0
void TMapUberPicture::SetMapInteractionMode(short nMode) {
  short previousMode = activeUnitCategoryIndex;
  if (previousMode != nMode) {
    if (previousMode == 0) {
      g_pSelectedCivilianOrderState->SelectUnit(NULL, false);
    } else if (previousMode == 1) {
      g_pMapContextActionManager->SetSelectedProvince(-1);
    }

    TToolBarCluster* toolbar =
        static_cast<TToolBarCluster*>(GetWindow()->FindSubView(kControlTagTbr1)); // 'tbr1'
    if (toolbar != NULL) {
      if (previousMode == 1) {
        TView* caption = toolbar->FindSubView(kControlTagForc); // 'forc'
        caption->AssertValid();
        caption->controlTag = kControlTagSeas; // 'seas'

        CString seasonCaption;
        CString yearCaption;
        g_pSimMgr->GetString(0x2730, 0x12, &seasonCaption);
        g_pSimMgr->GetString(0x2730, 8, &yearCaption);
        CString hoverHelp = seasonCaption + g_szListSeparator + yearCaption;
        SetControlHoverHelpTextAltEntry(hoverHelp, caption);
      } else if (nMode == 1) {
        CString hoverHelp;
        TView* caption = toolbar->FindSubView(kControlTagSeas); // 'seas'
        caption->AssertValid();
        caption->controlTag = kControlTagForc; // 'forc'
        g_pSimMgr->GetString(0x2732, 0x11, &hoverHelp);
        SetControlHoverHelpTextAltEntry(hoverHelp, caption);
      }

      toolbar->SetReadouts(g_pSimMgr->GetPlayerCountry());
    }

    if (nMode == 0) {
      EnterMapInteractionOverlayMode(NULL);
    }
  }

  if (previousMode < 3) {
    categoryPages[previousMode]->Locate(g_MapUberModeLayoutScratch, true);
  }
  activeUnitCategoryIndex = nMode;
  if (nMode < 3) {
    categoryPages[nMode]->Locate(g_MapUberModeLayoutTable[nMode], true);
  }
}

// FUNCTION: IMPERIALISM 0x00597020
void ComposeAndDispatchTurnSummaryLocalizedMessage() {
  CString summary;
  CString tempMsg;

  if (strcmp(g_szEmptyString, static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText)) != 0) {
    g_pSimMgr->GetString(0x273f, 1, &tempMsg);
    scanBracketExpressions(g_pSimMgr, &summary, static_cast<LPCSTR>(tempMsg),
                           static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText));
  }

  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    CString sectionMsg;
    g_pSimMgr->GetString(0x2742, 0x24, &tempMsg);
    scanBracketExpressions(g_pSimMgr, &sectionMsg, static_cast<LPCSTR>(tempMsg),
                           static_cast<LPCSTR>(g_pGameFlowState->gameNameString));
    summary += sectionMsg;
  }

  CString versionText = g_pAssetMgr->FormatVersionStringFromVersionResource();

  if (strcmp(g_szEmptyString, static_cast<LPCSTR>(versionText)) != 0) {
    if (strcmp(g_szEmptyString, static_cast<LPCSTR>(summary)) != 0) {
      summary += s_szDoubleNewline;
    }
    summary += versionText;
  }

  if (strcmp(g_szEmptyString, static_cast<LPCSTR>(summary)) != 0) {
    g_pViewMgr->ModalMessage(summary, g_ptMapModeModalMessage, 0, 0);
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
      if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
        CString msg;
        g_pSimMgr->GetString(0x2742, 0x25, &msg);
        g_pViewMgr->ModalMessage(msg, g_ptMapModeModalMessage, 0, 0);
      } else {
        ReinitializeGameFlowAndPostTurnEventCode(kTurnEventRandomGameSetup);
      }
      return;
    } else if (tag == kControlTagSend) {
      if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
        if (g_pGameFlowState->networkSavePending != 0) {
          g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalNetworkGameOptions);
        }
        // else: falls through with no further action in the original.
        return;
      }
      g_pGameFlowState->PoseMessageDialog(-1);
      return;
    }
  } else if (commandId == 0xc) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= kControlTagAgr0 && tag <= kControlTagAgr2) {
      TTaskForce* taskForce = g_pActiveMapOrderContext->selectedTaskForce;
      if (taskForce != NULL) {
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

  switch (activeUnitCategoryIndex) {
  case 0:
    if (g_pSelectedCivilianOrderState->selectedEntry != 0) {
      CenterOn(g_pSelectedCivilianOrderState->selectedEntry->tileIndex);
    }
    return;

  case 1:
    if (g_pMapContextActionManager->pendingMapActionIndex != -1) {
      CenterOn(g_pGlobalMapState->cityScoreTable[g_pMapContextActionManager->pendingMapActionIndex]
                   .cityTileIndex);
    }
    return;

  case 2:
    if (orderEntryContext != 0) {
      CenterOn(orderEntryContext->tileOrTerrainId);
    }
    return;

  case 3:
    CenterOn(
        g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(g_pSimMgr->GetPlayerCountry()));
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00597770
void TMapUberPicture::DoKeyEvent(TToolboxEvent* event) {
  if (subview != 0) {
    subview->DoKeyEvent(event);
  }
}

// FUNCTION: IMPERIALISM 0x005977a0
void TMapUberPicture::Scroll(MapScrollEdgeMaskStorage edgeMask) {
  if (invalidationFlag) {
    subview2A8->UpdateMapInteractionPreviewParityAndRenderTransientSprites(edgeMask);
  } else {
    goodGoldTagControl->ApplyDirectionalNudgeAndRefreshDisplay(
        static_cast<unsigned char>(edgeMask));
  }
  if (miniMapView != NULL) {
    miniMapView->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00597810
void TMapUberPicture::FocusOnForce(TTaskForce* pMapOrderEntry) {
  SetMapInteractionMode(2);
  ResetMapActionContextActivityAndNationFlags();

  if (pMapOrderEntry == NULL) {
    for (int i = 0; i < 4; ++i) {
      TShipFractionCluster* shipClass =
          static_cast<TShipFractionCluster*>(FindSubView(kControlTagCls0 + i)); // 'cls0'..'cls3'
      shipClass->AssertValid();
      shipClass->Set(0, -1);
    }
    return;
  }

  TZone* context = pMapOrderEntry->location;
  context->LightUp(pMapOrderEntry->GetWorstSpeed(), true);
  CenterOn(static_cast<short>(context->tileOrTerrainId));

  for (int i = 0; i < 4; ++i) {
    TShipFractionCluster* shipClass =
        static_cast<TShipFractionCluster*>(FindSubView(kControlTagCls0 + i)); // 'cls0'..'cls3'
    shipClass->AssertValid();
    shipClass->Set(pMapOrderEntry->shipCountsByToolbarSlot[i],
                   pMapOrderEntry->GetSelected(static_cast<short>(i)));
  }

  TNavyToolbarCluster* navyToolbar =
      static_cast<TNavyToolbarCluster*>(FindSubView(kControlTagUnav)); // 'unav'
  navyToolbar->AssertValid();
  navyToolbar->SetCurrentChoice(kControlTagAgr0 + pMapOrderEntry->aggression);
}

// FUNCTION: IMPERIALISM 0x00597950
void TMapUberPicture::FocusOnZone(TZone* pMapOrderContextZone) {
  SetMapInteractionMode(2);
  goodGoldTagControl->InvalidateZone(orderEntryContext);
  orderEntryContext = pMapOrderContextZone;
  goodGoldTagControl->InvalidateZone(pMapOrderContextZone);
  if (pMapOrderContextZone == NULL) {
    FocusOnForce(NULL);
    return;
  }
  TTaskForce* refreshedTaskForce = g_pActiveMapOrderContext->AssembleUIForce(pMapOrderContextZone);
  FocusOnForce(refreshedTaskForce);
}

// FUNCTION: IMPERIALISM 0x00597a10
bool TMapUberPicture::IsAUnitSelected() {
  switch (activeUnitCategoryIndex) {
  case 0:
    return g_pSelectedCivilianOrderState->selectedEntry != NULL;
  case 1:
    return g_pMapContextActionManager->pendingMapActionIndex != -1;
  case 2:
    return g_pActiveMapOrderContext->selectedTaskForce != NULL;
  default:
    return false;
  }
}

// FUNCTION: IMPERIALISM 0x00597a80
void TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick() {
  unsigned char modeCursor = static_cast<unsigned char>(activeUnitCategoryIndex);
  unsigned char visitedModes = 0;
  bool selectionResolved = false;
  unsigned char previousMode = modeCursor;

  short activeNation = g_pSimMgr->GetPlayerCountry();
  if (!g_pSimMgr->ReallyInTheGame(activeNation)) {
    visitedModes = 7;
  }

  while (visitedModes != 7 && !selectionResolved) {
    switch (modeCursor) {
    case 0: {
      if (previousMode != 0) {
        g_pSelectedCivilianOrderState->ResetCycle(g_pSimMgr->GetPlayerCountry());
        visitedModes |= 1;
      }

      TCivUnit* civilian = g_pSelectedCivilianOrderState->Cycle(g_pSimMgr->GetPlayerCountry());
      if (civilian != NULL) {
        selectionResolved = true;
        if (activeUnitCategoryIndex != 0) {
          EnterMapInteractionOverlayMode(NULL);
          SetMapInteractionMode(0);
        }
        g_pSelectedCivilianOrderState->SelectUnit(civilian, true);
        CenterOn(civilian->tileIndex);
        ForceRedraw();
      } else {
        modeCursor = 1;
        previousMode = 0;
        if (activeUnitCategoryIndex != 0) {
          visitedModes |= 1;
        }
      }
      break;
    }

    case 1: {
      if (previousMode != 1) {
        g_pMapContextActionManager->ResetCycle(g_pSimMgr->GetPlayerCountry());
        visitedModes |= 2;
      }

      short province = g_pMapContextActionManager->Cycle(g_pSimMgr->GetPlayerCountry());
      if (province != -1) {
        if (activeUnitCategoryIndex != 1) {
          SetMapInteractionMode(1);
        }
        g_pMapContextActionManager->SetSelectedProvince(province);
        CenterOn(g_pGlobalMapState->cityScoreTable[province].cityTileIndex);
        selectionResolved = true;
      } else {
        modeCursor = 2;
        previousMode = 1;
        if (activeUnitCategoryIndex != 1) {
          visitedModes |= 2;
        }
      }
      break;
    }

    case 2:
      if (TrySelectNextValidMapOrderEntry(false)) {
        selectionResolved = true;
      } else {
        modeCursor = 0;
        orderEntryContext = NULL;
        previousMode = 2;
        visitedModes |= 4;
      }
      break;

    case 3:
      modeCursor = 0;
      break;
    }
  }

  if (visitedModes == 7 && !selectionResolved) {
    selectionResolved = TrySelectNextValidMapOrderEntry(false);
  }

  if (selectionResolved) {
    return;
  }

  switch (activeUnitCategoryIndex) {
  case 0:
    g_pSelectedCivilianOrderState->selectedEntry = NULL;
    break;
  case 1:
    g_pMapContextActionManager->SetSelectedProvince(-1);
    SetMapInteractionMode(3);
    return;
  case 2:
    SetMapInteractionMode(2);
    InvalidateMapRegionForEntryIfUiPassive(orderEntryContext);
    orderEntryContext = NULL;
    InvalidateMapRegionForEntryIfUiPassive(NULL);
    FocusOnForce(NULL);
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

  // ORACLE: Mac MapView.rsrc:9474, event 0x2502, "Friendly Fleet Report".
  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventFriendlyFleetReport));
  if (dialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0x728);
  }
  dialog->SetModality(true);

  CString text;
  CString value;
  CString reportTemplate;
  TStaticText* control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagZone)); // zone
  control->AssertValid();
  taskForce->location->AssignZoneDisplayNameToOutputRef(&text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagAdam)); // adam
  control->AssertValid();
  taskForce->GetAuthority(&value);
  g_pSimMgr->GetString(0x2762, 0, &reportTemplate);
  scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                         static_cast<LPCSTR>(value));
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagWhom)); // whom
  control->AssertValid();
  taskForce->GetCompositionDescription(&text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagOrds)); // ords
  control->AssertValid();
  switch (taskForce->shipOrders) {
  case 1:
    static_cast<TZone*>(taskForce->target)->AssignZoneDisplayNameToOutputRef(&value);
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
    static_cast<TZone*>(taskForce->target)->AssignZoneDisplayNameToOutputRef(&value);
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0x39);
    scanBracketExpressions(g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(value));
    break;
  default:
    g_pSimMgr->GetString(0x2762, 3, &text);
    break;
  }
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagAgro)); // agro
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(taskForce->aggression + 4), &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(attributionStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagTitl)); // titl
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 7, &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(titleStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab1)); // lab1
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 8, &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab2)); // lab2
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 9, &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab3)); // lab3
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, 0xa, &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(bodyStyle, 0);

  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }
  int result = dialog->PoseModally();
  dialog->Close();
  dialog->Free();

  if (result == kControlTagCanc) { // 'canc'
    TZone* previousContext = taskForce->location;
    taskForce->CancelOrders(0);
    SetMapInteractionMode(2);
    goodGoldTagControl->InvalidateZone(orderEntryContext);
    orderEntryContext = previousContext;
    goodGoldTagControl->InvalidateZone(previousContext);
    TTaskForce* refreshed =
        previousContext != 0 ? g_pActiveMapOrderContext->AssembleUIForce(previousContext) : 0;
    FocusOnForce(refreshed);
  }
}

// FUNCTION: IMPERIALISM 0x00598840
void TMapUberPicture::InvalidateMapRegionForEntryIfUiPassive(TZone* zone) {
  if (!invalidationFlag) {
    goodGoldTagControl->InvalidateZone(zone);
  }
}

// FUNCTION: IMPERIALISM 0x00598870
void TMapUberPicture::InvalidateTile(short tileIndex) {
  if (invalidationFlag) {
    subview2A8->InvalidateTile(tileIndex);
  } else {
    goodGoldTagControl->InvalidateTile(tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005988c0
void TMapUberPicture::RedrawTile(short tileIndex) {
  subview->ImmediateDrawTile(tileIndex);
  if (!invalidationFlag) {
    subview2A8->DeCache(tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x00598910
void TMapUberPicture::DisplayInfo(bool showInfo) {
  PrepareForDrawing();
  subview->SetMapOverlayModeAndRenderPreview(showInfo);
}

// FUNCTION: IMPERIALISM 0x00598950
void TMapUberPicture::InvalidateMap() {
  if (invalidationFlag) {
    subview2A8->RefreshControl();
  } else {
    goodGoldTagControl->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00598990
void TMapUberPicture::CenterOn(int tileIndex) {
  subview->CenterOn(tileIndex);
  if (miniMapView != NULL) {
    miniMapView->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005989d0
void TMapUberPicture::SetUpperLeft(int tileX, int tileY) {
  subview->SetMapViewCellCoordinates(tileX, tileY);
  if (miniMapView != NULL) {
    miniMapView->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00598a20
void TMapUberPicture::NoticeTile(int tileIndex) {
  subview->NoticeTile(tileIndex);
}

// FUNCTION: IMPERIALISM 0x00598a50
void TMapUberPicture::ArmyCheatClick(short provinceIndex) {
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[provinceIndex].cityRecordIndex;
  if (cityRecordIndex == -1) {
    return;
  }
  RGBQUAD hiliteColor;
  hiliteColor.rgbBlue = 0xff;
  hiliteColor.rgbGreen = 0xff;
  hiliteColor.rgbRed = 0xff;
  hiliteColor.rgbReserved = 0;
  g_pDisplayMgr->SetHiliteColor(&hiliteColor);

  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(static_cast<TurnEventId>(0x24f4)));
  if (dialog == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\USuperMap.cpp", 0x846);
  }
  dialog->SetModality(true);

  short ownerNation = g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode;

  // Label the 30 army-name slots from the localized army-name string group.
  for (int slot = 0; slot < 0x1e; ++slot) {
    TStaticText* nameLabel = static_cast<TStaticText*>(
        dialog->FindSubView(IMPERIALISM_FOURCC('n', 'a', 'm', 'a') + slot));
    nameLabel->AssertValid();
    nameLabel->SetTextWithStrListID(0x2717, static_cast<short>(slot + 1), true);
  }
  dialog->PoseModally();

  // Read the per-slot unit counts the player entered and spawn that many units each.
  for (int countSlot = 0; countSlot < 0x1e; ++countSlot) {
    TNumberText* countField = static_cast<TNumberText*>(
        dialog->FindSubView(IMPERIALISM_FOURCC('n', 'u', 'm', 'a') + countSlot));
    countField->AssertValid();
    int unitCount = countField->UpdateControlCachedIntFromWindowText();
    for (int made = 0; made < unitCount; ++made) {
      TMilitaryUnit* unit = new TMilitaryUnit();
      unit->IMilitaryUnit(0, provinceIndex, ownerNation, static_cast<short>(countSlot));
    }
  }
  dialog->Close();
  dialog->Free();

  CString prompt("Kill all armies in the province?");
  g_pViewMgr->ModalMessage(prompt, g_ptMapModeModalMessage, 1, 1);
}

// FUNCTION: IMPERIALISM 0x00598d70
void TMapUberPicture::CivilianCheatClick(int orderContext) {
  TCivUnit* unit = new TCivUnit();
  unit->ICivUnit(kCivilianUnitProspector, orderContext, 0);
  InvalidateTile(static_cast<short>(orderContext));
}

// FUNCTION: IMPERIALISM 0x00598e10
void TMapUberPicture::RunNavyPrimaryOrderCreationDialogAndApplyResults(TZone* portZone) {
  if (portZone == 0) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0x8bf);
  }

  RGBQUAD highlightColor = {0xff, 0xff, 0xff, 0};
  g_pDisplayMgr->SetHiliteColor(&highlightColor);

  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNavyMaker));
  if (dialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0x8cc);
  }
  dialog->SetModality(true);

  short index;
  for (index = 0; index < 29; ++index) {
    TStaticText* nameControl =
        static_cast<TStaticText*>(dialog->FindSubView(kControlTagNama + index)); // 'nama'
    if (nameControl != 0) {
      nameControl->SetTextWithStrListID(0x2716, static_cast<short>(index + 1), true);
    }
  }

  dialog->PoseModally();

  TNumberText* ownerControl =
      static_cast<TNumberText*>(dialog->FindSubView(kControlTagOwne)); // 'owne'
  ownerControl->AssertValid();
  int ownerNation = ownerControl->UpdateControlCachedIntFromWindowText();

  bool createdOrders = false;
  for (index = 0; index < 14; ++index) {
    TNumberText* countControl =
        static_cast<TNumberText*>(dialog->FindSubView(kControlTagNuma + index)); // 'numa'
    if (countControl != 0) {
      short count = countControl->UpdateControlCachedIntFromWindowText();
      if (count != 0) {
        while (count > 0) {
          CreateNavyPrimaryOrderNodeAndAssignDisplayName(static_cast<short>(index), portZone,
                                                         ownerNation, 0);
          --count;
        }
        createdOrders = true;
      }
    }
  }

  dialog->Close();
  dialog->Free();

  if (createdOrders) {
    g_pActiveMapOrderContext->UpdateOccupants();
  }

  SetMapInteractionMode(2);
  if (!invalidationFlag) {
    goodGoldTagControl->InvalidateZone(orderEntryContext);
  }
  orderEntryContext = portZone;
  if (!invalidationFlag) {
    goodGoldTagControl->InvalidateZone(portZone);
  }

  if (portZone == 0) {
    FocusOnForce(0);
    return;
  }
  TTaskForce* taskForce = g_pActiveMapOrderContext->AssembleUIForce(portZone);
  FocusOnForce(taskForce);
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

  // ORACLE: Mac MapView.rsrc:9475, event 0x2503, "Enemy Fleet Report".
  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventEnemyFleetReport));
  if (dialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0x923);
  }
  dialog->SetModality(true);

  CString text;
  CString reportTemplate;
  TStaticText* control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagGpee)); // gpee
  control->AssertValid();
  g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagZone)); // zone
  control->AssertValid();
  zone->AssignZoneDisplayNameToOutputRef(&text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagAdam)); // adam
  control->AssertValid();
  if (cachedTaskForce != 0) {
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0x34);
    scanBracketExpressions(
        g_pSimMgr, &text, static_cast<LPCSTR>(reportTemplate),
        static_cast<LPCSTR>(static_cast<Province*>(cachedTaskForce->target)->cityName));
  } else {
    zone->GetNavalAuthority(&text, g_pSimMgr->GetPlayerCountry());
  }
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(attributionStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagShip)); // ship
  control->AssertValid();
  if (cachedTaskForce != 0) {
    cachedTaskForce->GetCompositionDescription(&text);
  } else {
    TAdmiral* observer = zone->GetSeniorOfficerOf(g_pSimMgr->GetPlayerCountry());
    observer->GetFleetReport(&text, zone, nation);
  }
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  int stringIndex = cachedTaskForce != 0 ? 0x2e : 0x29;
  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagTitl)); // titl
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(titleStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab1)); // lab1
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab2)); // lab2
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(detailStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab3)); // lab3
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex++), &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(dialog->FindSubView(kControlTagLab4)); // lab4
  control->AssertValid();
  g_pSimMgr->GetString(0x2762, static_cast<short>(stringIndex), &text);
  control->SetTextAndMaybeRefresh(&text, false);
  control->InstallTextStyle(attributionStyle, 0);

  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }
  dialog->PoseModally();
  dialog->Close();
  dialog->Free();
}

// FUNCTION: IMPERIALISM 0x00599770
void TMapUberPicture::NextSeaZonePlease(char includeCurrent) {
  if (activeUnitCategoryIndex != 2) {
    return;
  }

  g_pActiveMapOrderContext->AssembleUIForce(NULL);
  TZone* candidate = orderEntryContext;
  if (candidate != NULL && includeCurrent == 0) {
    candidate = candidate->prev18;
  }
  if (candidate == NULL) {
    candidate = g_pMapActionContextListHead;
  }

  while (candidate != NULL) {
    if (candidate->HasFreeShipsOfPlayer(-1, false)) {
      SetMapInteractionMode(2);
      InvalidateMapRegionForEntryIfUiPassive(orderEntryContext);
      orderEntryContext = candidate;
      InvalidateMapRegionForEntryIfUiPassive(candidate);
      if (candidate == NULL) {
        FocusOnForce(NULL);
        return;
      }
      TTaskForce* taskForce = g_pActiveMapOrderContext->AssembleUIForce(candidate);
      FocusOnForce(taskForce);
      return;
    }
    candidate = candidate->prev18;
  }
  orderEntryContext = NULL;
}

// FUNCTION: IMPERIALISM 0x005998a0
bool TMapUberPicture::TrySelectNextValidMapOrderEntry(bool includeCurrent) {
  g_pActiveMapOrderContext->AssembleUIForce(NULL);

  TZone* candidate = orderEntryContext;
  if (candidate != NULL && !includeCurrent) {
    candidate = candidate->prev18;
  }
  if (candidate == NULL) {
    candidate = g_pMapActionContextListHead;
  }

  while (candidate != NULL) {
    if (candidate->HasFreeShipsOfPlayer(-1, false)) {
      SetMapInteractionMode(2);
      InvalidateMapRegionForEntryIfUiPassive(orderEntryContext);
      orderEntryContext = candidate;
      InvalidateMapRegionForEntryIfUiPassive(candidate);
      if (candidate == NULL) {
        FocusOnForce(NULL);
        return true;
      }
      TTaskForce* taskForce = g_pActiveMapOrderContext->AssembleUIForce(candidate);
      FocusOnForce(taskForce);
      return true;
    }
    candidate = candidate->prev18;
  }

  orderEntryContext = NULL;
  return false;
}

// FUNCTION: IMPERIALISM 0x005999c0
void TMapUberPicture::GrandCycle() {
  if (invalidationFlag) {
    SetMapInteractionMode(1);
    return;
  }
  SetMapInteractionMode(2);
}

// FUNCTION: IMPERIALISM 0x005999f0
void TMapUberPicture::SwitchToCivilianMode() {
  EnterMapInteractionOverlayMode(NULL);
  SetMapInteractionMode(0);
}

// FUNCTION: IMPERIALISM 0x00599a20
void TMapUberPicture::UpdateRoster() {
  if (navyRoster != 0) {
    navyRoster->ShowPage(navyRoster->currentPage);
  }
}

// FUNCTION: IMPERIALISM 0x00599a50
void TMapUberPicture::EnterMapInteractionOverlayMode(TView* controlOverride) {
  if (invalidationFlag) {
    return;
  }
  TView* zoomControl = (controlOverride != NULL) ? controlOverride : FindSubView(kControlTagZmIn);
  zoomControl->AssertValid();
  if (zoomControl != NULL) {
    zoomControl->controlTag = kControlTagZmOt; // "ZmOt" ("Zoom Out")
  }
  invalidationFlag = true;

  subview2A8->CenterOn(goodGoldTagControl->GetCenterTile());

  goodGoldTagControl->Locate(g_MapUberModeLayoutScratch, false);
  subview2A8->Locate(g_MapUberModeSecondaryLayoutScratch, true);
  subview = subview2A8;

  if (miniMapView != NULL) {
    miniMapView->markerBoxWidth = g_defaultMarkerBoxWidth;
    miniMapView->markerBoxHeight = 8;
    miniMapView->markerBoxX = miniMapView->frameWidth / 2 - miniMapView->markerBoxWidth - 2;
    miniMapView->markerBoxY = miniMapView->frameHeight / 2 - miniMapView->markerBoxHeight - 2;
    miniMapView->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00599b90
void TMapUberPicture::CommitPendingUiModeChangeAndRefreshViews(TView* controlOverride) {
  if (invalidationFlag) {
    g_pUiAnimator->FreeAllAnis();
    TView* zoomControl = (controlOverride != NULL) ? controlOverride : FindSubView(kControlTagZmOt);
    zoomControl->AssertValid();
    if (zoomControl != NULL) {
      zoomControl->controlTag = kControlTagZmIn;
    }
    invalidationFlag = false;
    goodGoldTagControl->CenterOn(subview2A8->GetCentertile());
    subview2A8->Locate(g_MapUberModeLayoutScratch, false);
    goodGoldTagControl->Locate(g_MapUberModeSecondaryLayoutScratch, true);
    TMiniMapView* miniMap = miniMapView;
    subview = goodGoldTagControl;

    if (miniMap != NULL) {
      miniMap->markerBoxWidth = 0x20;
      miniMap->markerBoxHeight = 0x1c;
      miniMap->markerBoxX = miniMap->frameWidth / 2 - miniMap->markerBoxWidth - 2;
      miniMap->markerBoxY = miniMap->frameHeight / 2 - miniMap->markerBoxHeight - 2;
      miniMap->RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00599cf0
void TMapUberPicture::DisplayMiniMap() {
  TView* toolControl = FindSubView(kControlTagTool); // "tool"
  if (toolControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0xa56);
  }

  const int kToolWindowMargin = 4;
  TMiniMapView* miniMap = new TMiniMapView();
  int offsetLayout[2] = {kToolWindowMargin, 0x31};
  int sizeLayout[2] = {0x71, 0x41};
  miniMap->InitializeUiResourceEntryFrameAndParent(NULL, toolControl, offsetLayout, sizeLayout,
                                                   kToolWindowMargin, kToolWindowMargin, 0);
  miniMap->markerBoxX = miniMap->frameWidth / 2 - miniMap->markerBoxWidth;
  miniMap->ownerPicture = this;
  miniMap->markerBoxY = miniMap->frameHeight / 2 - miniMap->markerBoxHeight;
  miniMap->RefreshControl();
  miniMap->ViewEnable(1, 0);
  miniMapView = miniMap;

  RECT toolRect;
  toolRect.left = toolControl->ownerLocalX + offsetLayout[0];
  toolRect.top = toolControl->ownerLocalY + offsetLayout[1];
  toolRect.right = toolRect.left + 0x71;
  toolRect.bottom = toolRect.top + 0x41;
  RgnHandle region = NewRgn();
  RectRgn(region, &toolRect);
  UnionRgn(ownClipRegion, region, ownClipRegion);
  DisposeRgn(region);

  if (!invalidationFlag) {
    miniMapView->markerBoxWidth = 0x20;
    miniMapView->markerBoxHeight = 0x1c;
    miniMapView->markerBoxX = miniMapView->frameWidth / 2 - miniMapView->markerBoxWidth - 2;
    miniMapView->markerBoxY = miniMapView->frameHeight / 2 - miniMapView->markerBoxHeight - 2;
    miniMapView->RefreshControl();
  }

  SetTradeToolSubcontrolEnabledStateByFlag(false);
}

// FUNCTION: IMPERIALISM 0x00599fa0
void TMapUberPicture::InvalidateMiniMap() {
  if (this != 0 && miniMapView != 0) {
    miniMapView->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00599fd0
void TMapUberPicture::RemoveMiniMap() {
  TView* toolControl = FindSubView(kControlTagTool); // 'tool'
  if (toolControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0xa97);
  }

  CRect mapBounds;
  subview->GetFrame(&mapBounds);
  RgnHandle mapRegion = NewRgn();
  RectRgn(mapRegion, &mapBounds);
  SetRgn(mapRegion);
  DisposeRgn(mapRegion);

  RECT toolRect;
  toolRect.left = toolControl->ownerLocalX + 5;
  toolRect.top = toolControl->ownerLocalY + 0x37;
  toolRect.right = toolControl->ownerLocalX + 0x76;
  toolRect.bottom = toolControl->ownerLocalY + 0x78;
  InvalidateCityDialogRectRegion(&toolRect, 1);

  if (miniMapView != NULL) {
    miniMapView->Free();
  }
  miniMapView = NULL;

  TPicture* miniMapButton =
      static_cast<TPicture*>(toolControl->FindSubView(kControlTagInfo)); // 'info'
  if (miniMapButton == NULL) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0xab4);
  }
  miniMapButton->SetPictureRsrcID(0x41a, true);
  miniMapButton->controlTag = kControlTagMmap; // 'mmap'
  SetTradeToolSubcontrolEnabledStateByFlag(true);
}

// FUNCTION: IMPERIALISM 0x0059a180
void TMapUberPicture::SetTradeToolSubcontrolEnabledStateByFlag(bool enabledState) {
  TView* toolControl = FindSubView(kControlTagTool); // "tool"
  if (toolControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUSuperMap, 0xac7);
  }

  TView* seasControl = toolControl->FindSubView(kControlTagSeas); // "seas"
  if (seasControl != NULL) {
    seasControl->Show(enabledState, 1);
  }
  TView* yearControl = toolControl->FindSubView(kControlTagYear); // "year"
  if (yearControl != NULL) {
    yearControl->Show(enabledState, 1);
  }
  TView* treaControl = toolControl->FindSubView(kControlTagTrea); // "trea"
  if (treaControl != NULL) {
    treaControl->Show(enabledState, 1);
  }
  TView* treeControl = toolControl->FindSubView(kControlTagTree); // "tree"
  if (treeControl != NULL) {
    treeControl->Show(enabledState, 1);
  }
}
