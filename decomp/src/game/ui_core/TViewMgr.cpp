#include "game/ui_core/TViewMgr.h"
#include "game/military_ui/TTechCheater.h"
#include "game/TGPCheater.h"
#include "game/GameAssert.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_widgets.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_widgets/TArmyInfoView.h"
#include "game/city_ui/TBuildingExpansionView.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_widgets/TCivReport.h"
#include "game/city/TTown.h"
#include "game/ui_screens/TOffLimitsPicture.h"
#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/city_ui/TPlaceCityDialog.h"
#include "game/ui_widgets/TCombatReportView.h"

#include "game/trade_ui/TDealBookPicture.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/gfx/TResourceMgr.h"

#include "game/resource_domain_types.h"

#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TSoundPlayer.h" // g_pSfxPlaybackSystem
#include "game/ui_core/TMacViewMgr.h"     // g_pMacViewMgr
#include "game/ui_core/TIncludeView.h"    // turn-event UI entry packet ('Incl')
#include "game/ui_core/CWMgrIterator.h"   // window-registry traversal for the full (code-0) refresh
#include "game/ui_core/quickdraw_rendering.h" // SetQuickDrawFillColor / SetQuickDrawStrokeColor
#include "game/ui_widgets/TToolBarCluster.h" // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/ui_widgets/TTradeCluster.h"
#include "game/assets/TMovieView.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/city_ui/TCountry.h" // FormatOverlayTerrainLabelText (terrain overlay case)
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TPtrList.h"
#include "game/military/TGarrisonView.h"
#include "game/map/TMapMgr.h"
#include "game/gfx/TDisplayMgr.h" // g_pDisplayMgr, g_szUiNilPointerMessage, g_szUiFailureMessage
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/app/TCouncilTickerAnimation.h"
#include "game/diplomacy_ui/TCouncilView.h"
#include "game/gfx/CTemporaryRegion.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_screens/turn_flow_cooldown.h" // IsTurnFlowCooldownActiveAndResetExpiredState
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/ui_message_pump.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TCluster.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_core/TModalMessageCommand.h"
#include "game/ui_core/TApplication.h"
#include "game/military_ui/TSuperCivRoster.h"
#include "game/military_ui/TSuperArmyRoster.h"
#include "game/navy_ui/TSuperNavyRoster.h"
#include "game/navy_ui/TNavyRoster.h"
#include "game/navy/TTaskForce.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif
#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_screens/TScrollView.h" // nation-info modal overflow scroll wrapper
#include "game/ui_core/TStaticText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_widgets/TDropShadowNumberText.h"
#include "game/ui_widgets/TGPTreatyDialog.h"
#include "game/ui_widgets/TMinorRelationshipDialog.h"
#include "game/ui_widgets/TMinorTradeBidsDialog.h"
#include "game/ui_widgets/TMinorTreatyDialog.h"
#include "game/ui_widgets/TRelationshipDialog.h"
#include "game/app/TTechStorePage.h"
#include "game/military/mapped_flavor_text.h" // BuildUiMessageTextFromBracketTemplate / scanBracketExpressions
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TRadioText.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/city_ui/TCivMgr.h"
#include "game/military/TCivUnit.h"
#include "game/city/TCity.h"
#include "game/map_ui/TCitySiteView.h"
#include "game/ui_widgets/TWorldView.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_text_label_helpers_decls.h"

#include <new>

#include "game/ui_core/CIncludeView.h"

namespace {
const unsigned int kAddrClassDescTViewMgr = 0x0066f0b8;
} // namespace

HCURSOR LoadTurnEventCursorByResourceIdOffset1000(short cursorResourceId);

IMPLEMENT_DYNCREATE(TViewMgr, TObject)

// FUNCTION: IMPERIALISM 0x005d5060
TViewMgr::TViewMgr() {
  this->pendingTurnOverlayCode = 0;
  this->currentTurnEventCode = 0;
  this->dialogPlacement = g_ptCitySiteSelectionDialogPlacement;
  this->waitOverlayPending = false;
  this->mapUberPicture = 0;
  this->activeMovieView = 0;
  this->pendingFollowupState = 0;
}

TViewMgr::~TViewMgr() {}

// FUNCTION: IMPERIALISM 0x005d5100
void TViewMgr::LoadTurnEventCursorTable() {
  for (int i = 0; i < 0x36; i++) {
    turnEventCursors[i] = LoadTurnEventCursorByResourceIdOffset1000(i + 1000);
  }
}

// FUNCTION: IMPERIALISM 0x005d5140
HCURSOR LoadTurnEventCursorByResourceIdOffset1000(short cursorResourceId) {
  CString cursorName;
  cursorName.Format(s_TurnEventCursorNameFormat, cursorResourceId);
  (void)AfxGetModuleState();
  return LoadCursorA(AfxGetResourceHandle(), cursorName);
}

// FUNCTION: IMPERIALISM 0x005d51e0
void TViewMgr::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x005d5200
void TViewMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  pendingTurnOverlayCode = 0;
  currentTurnEventCode = 0;
  dialogPlacement = g_ptCitySiteSelectionDialogPlacement;
  waitOverlayPending = false;
  mapUberPicture = 0;
}

// FUNCTION: IMPERIALISM 0x005d5250
void TViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x005d5270
QuickDrawPaletteIndex TViewMgr::GetColor(short eventCode) {
  if (eventCode > 200) {
    if (eventCode < 0x2b68) {
      if (eventCode == 0x2b67) {
        return 0;
      }
      switch (eventCode) {
      case 0xc9:
        return 0x2d;
      case 0xca:
        return 0x30;
      case 0xcb:
        return 0x2e;
      case 0xcc:
        return 0x27;
      case 0xcd:
        return 0x24;
      case 0xce:
        return 0x26;
      case 0xcf:
        return 0x18;
      case 0xd0:
        return 0x14;
      }
    } else {
      switch (eventCode) {
      case 0x2b68:
        return 0x13;
      case 0x2b69:
        return 0xcb;
      case 0x2b6a:
        return 0x5c;
      case 0x2b6b:
        return 0xd2;
      case 0x2b6c:
        return 0x28;
      case 0x2b6d:
        return 1;
      }
    }
    return 0xff;
  }
  if (eventCode != 200) {
    switch (eventCode) {
    case 0:
      return 0x16;
    case 1:
      return 0x2a;
    case 2:
    case 0x40:
      return 0x22;
    case 3:
    case 0x3c:
    case 0x4e:
      return 0x1c;
    case 4:
      return 0x2b;
    case 5:
      return 0x1e;
    case 6:
      return 0x2e;
    case 7:
    case 0x35:
      return 10;
    case 8:
    case 0x3d:
      return 0xb;
    case 9:
      return 0xd;
    case 10:
    case 0x43:
      return 0x29;
    case 0xb:
      return 0xde;
    case 0xc:
    case 0x47:
      return 0xdf;
    case 0xd:
    case 0x49:
      return 0xfa;
    case 0xe:
    case 0x38:
      return 0x2c;
    case 0xf:
    case 0x4a:
      return 0x31;
    case 0x10:
      return 0x33;
    case 0x11:
      return 0x41;
    case 0x12:
      return 0x48;
    case 0x13:
      return 0xd0;
    case 0x14:
      return 0xcd;
    case 0x15:
      return 0xce;
    case 0x16:
      return 0xcf;
    default:
      return 0xff;
    case 0x25:
    case 0x3f:
      break;
    case 0x32:
      return 0x1a;
    case 0x33:
      return 0x2d;
    case 0x34:
      return 0x18;
    case 0x37:
      return 0xbd;
    case 0x3a:
      return 0xc6;
    case 0x3b:
      return 0x27;
    case 0x3e:
      return 0x15;
    case 0x41:
      return 0x1b;
    case 0x42:
      return 0x21;
    case 0x44:
      return 0x17;
    case 0x45:
      return 0x5f;
    case 0x46:
      return 0xbe;
    case 0x48:
      return 100;
    case 0x4b:
      return 0x66;
    case 0x4c:
      return 0x89;
    case 0x4d:
      return 0xad;
    case 0x4f:
      return 0xe7;
    case 0x50:
      return 0xe6;
    case 0x51:
      return 0xf6;
    case 0x52:
      return 0xc;
    case 0x53:
      return 0xef;
    case 0x54:
      return 0xf9;
    }
  }
  return 0x20;
}

// FUNCTION: IMPERIALISM 0x005d5710
void TViewMgr::SetColor(short colorCode, bool foreground) {
  QuickDrawPaletteIndex paletteIndex = GetColor(colorCode);
  if (foreground) {
    SetQuickDrawFillColorFromPaletteIndex(static_cast<unsigned short>(paletteIndex));
  } else {
    UpdatePaletteIndexWithDefaultFallback(paletteIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005d5750
void TViewMgr::SetForeColor(short colorCode) {
  QuickDrawPaletteIndex paletteIndex = GetColor(colorCode);
  SetQuickDrawFillColorFromPaletteIndex(static_cast<unsigned short>(paletteIndex));
}

// FUNCTION: IMPERIALISM 0x005d5780
void TViewMgr::SetBackColor(short colorCode) {
  QuickDrawPaletteIndex paletteIndex = GetColor(colorCode);
  UpdatePaletteIndexWithDefaultFallback(paletteIndex);
}

// FUNCTION: IMPERIALISM 0x005d57b0
void TViewMgr::VerifyEndTurn() {
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return;
  }
  TWindow* node = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventConfirmEndTurn);
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x223);
  }
  node->SetModality(true);
  if (node->FindSubView(kControlTagDialog) == NULL) { // 'GOLD'
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x227);
  }
  TDialogBehavior* content = node->GetDialogBehavior();
  if (content != NULL) {
    content->defaultCommandCode = kControlTagPic5; // 'cip5'
  }

  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);

  TPicture* gold = static_cast<TPicture*>(node->FindSubView(kControlTagDialog)); // 'DLOG'
  gold->AssertValid();
  gold->SetPictureRsrcID(static_cast<short>(0x24cd), 0);

  // Mask the game-flow flag while committing the refresh when localization mode is active.
  unsigned char savedFlag = 0;
  bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
  if (multiplayerActive) {
    savedFlag = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
  }
  node->PoseModally();
  node->Close();
  node->Free();
  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->processPrimaryEventQueue = savedFlag;
  }
}

// FUNCTION: IMPERIALISM 0x005d5960
int TViewMgr::ClassifyTurnStateForOverlayMode() {
  switch (static_cast<short>(g_pSimMgr->mode)) {
  case kGamePhaseDiplomacy:
  case kGamePhaseDealBook:
  case kGamePhaseCouncil:
  case kGamePhaseNews:
  case kGamePhaseOptionalDealBook:
  case kGamePhaseOptionalNewspaper:
  case kGamePhaseOptionalTradeOverview:
  case kGamePhaseOptionalDiplomacyMap:
    return 0;
  case kGamePhaseMilitary:
  case kGamePhaseBattleReport:
  case kGamePhaseCombat:
  case kGamePhaseProduction:
  case kGamePhaseCouncilVictory:
  case kGamePhaseCouncilDefeat:
  case kGamePhaseEliminations:
  case kGamePhaseOptionalBattleReport:
    return 1;
  case kGamePhaseOptionalCityScreen:
    return 2;
  default:
    return 2;
  }
}

// FUNCTION: IMPERIALISM 0x005d5a70
void TViewMgr::ModalMessage(CString message, const POINT& messagePosition) {
  int overlayMode = ClassifyTurnStateForOverlayMode();
  ModalMessage(message, messagePosition, overlayMode, 0);
}

// FUNCTION: IMPERIALISM 0x005d5b00
bool TViewMgr::ModalMessage(CString message, const POINT& messagePosition, short overlayMode,
                            unsigned char showCancel) {
  return ModalMessage(3, CString(g_szEmptyString), message, messagePosition, overlayMode,
                      showCancel);
}

// FUNCTION: IMPERIALISM 0x005d5bc0
bool TViewMgr::ModalMessageGateAssertStub(CString message, int arg2, int arg3, int arg4, int arg5,
                                          int arg6) {
  if (g_nViewMgrModalAssertGate == 0) {
    ReportAssertionFailure(s_SourcePathUViewMgr, 0x2ac);
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005d5c40
bool TViewMgr::ModalMessage(long templateKind, CString titleSuffix, CString message,
                            const POINT& messagePosition, short overlayMode,
                            unsigned char showCancel) {
  return RunNationInfoModalAndReturnNonCancel(templateKind, titleSuffix,
                                              static_cast<LPCSTR>(message), message.GetLength(),
                                              messagePosition, overlayMode, showCancel);
}

// FUNCTION: IMPERIALISM 0x005d5d30
bool TViewMgr::RunNationInfoModalAndReturnNonCancel(int messageKind, CString titleSuffix,
                                                    const char* messageChars, int messageLength,
                                                    const POINT& messagePosition, short contextTag,
                                                    char showCancel) {
  CString titleText;
  TextStyle styleDescriptor;
  CRect bounds;            // function-scope like the original (0x38): not overlapped with the
  short overlaySfxIds[13]; // sfx table (0x48), so the frame keeps both live regions
  int payloadResource;
  styleDescriptor.textColor = 0;
  payloadResource = 0;
  if (messagePosition.x == -1000) {
    payloadResource = static_cast<short>(messagePosition.y);
  }
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);

  TWindow* dialog;
  if (static_cast<short>(payloadResource) == 0) {
    dialog = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMinisterMessage);
  } else {
    g_pAssetMgr->OpenFilesFor(0xb);
    dialog = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMinisterReward);
  }
  if (dialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x2e9);
  }
  dialog->SetModality(true);
  TDialogBehavior* content = dialog->GetDialogBehavior();
  if (content != 0) {
    content->defaultCommandCode = kControlTagOkay; // 'okay'
  }

  CPoint placement;
  GetTopLeftFor(dialog, &placement);
  dialog->Locate(placement, false);

  TPicture* gold = static_cast<TPicture*>(dialog->FindSubView(kControlTagDialog)); // 'DLOG'
  gold->AssertValid();
  if (gold == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x2fa);
  }
  int contextTagSx = contextTag;
  int goldResource = contextTagSx * 2 + 0x24cd;
  if (contextTag == 2 && g_nationInfoGoldResourceOverride != 0) {
    goldResource = g_nationInfoGoldResourceOverride;
  }
  gold->SetPictureRsrcID(static_cast<short>(goldResource), 0);

  TPicture* coat = static_cast<TPicture*>(dialog->FindSubView(kControlTagCoat)); // 'coat'
  coat->AssertValid();
  if (coat == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x301);
  }
  if (g_pSimMgr->GetPlayerCountry() >= 0 && g_pSimMgr->GetPlayerCountry() < kMajorNationCount) {
    coat->SetPictureRsrcID(static_cast<short>(g_pSimMgr->GetPlayerCountry() + 0x251c), 0);
  } else {
    coat->Show(0, 0);
  }

  if (static_cast<short>(payloadResource) != 0) {
    TPicture* goldValue = static_cast<TPicture*>(dialog->FindSubView(kControlTagDialog)); // 'DLOG'
    goldValue->AssertValid();
    goldValue->SetPictureRsrcID(static_cast<short>(contextTag + 0x252a), 0);
    TPicture* award = static_cast<TPicture*>(dialog->FindSubView(kControlTagRewa)); // 'awer'
    award->AssertValid();
    award->SetPictureRsrcID(static_cast<short>(payloadResource), 0);
  } else {
    TStaticText* title = static_cast<TStaticText*>(dialog->FindSubView(kControlTagTitl)); // 'titl'
    title->AssertValid();
    if (title == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x31a);
    }
    title->InstallTextStyle(styleDescriptor, 0);
    title->SetJustification(1, false);
    BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &titleText, 0x2749, messageKind, 0x2749,
                                          contextTagSx);
    titleText += '\r';
    titleText += '\r';
    titleText += titleSuffix;
    title->SetTextAndMaybeRefresh(&titleText, false);
  }

  TDeluxeText* info = static_cast<TDeluxeText*>(dialog->FindSubView(kControlTagInfo)); // 'info'
  info->AssertValid();
  info->StuffBuffer(messageChars, messageLength);
  info->SetTextStyle(styleDescriptor, false);
  int measuredHeight = static_cast<short>(info->MeasureCurrentTextHeightInLayoutRect());
  if (measuredHeight > info->frameHeight) {
    info->GetFrame(&bounds);
    bounds.right = bounds.top - 10;
    info->SetFrame(&bounds, false);
    if (measuredHeight > info->frameHeight) {
      TScrollView* scrollView = new TScrollView();
      scrollView->IScrollView(gold, &info->ownerLocalX, &info->frameWidth);
      scrollView->DoPostCreate(0);
      gold->RemoveSubView(info);
      scrollView->AttachChildControl(info, 0);
      bounds.top = 0;
      bounds.left = 0;
      bounds.bottom = measuredHeight;
      bounds.right = info->frameWidth - 0x1c;
      info->SetFrame(&bounds, false);
      scrollView->contentView = info;
      scrollView->Reset();
    }
  }

  if (showCancel != 0) {
    TView* cancel = dialog->FindSubView(kControlTagCncl); // 'cncl'
    cancel->AssertValid();
    cancel->Show(1, 1);
    cancel->ViewEnable(1, 0);
  }

  unsigned char savedProcessFlag;
  bool simSuppressed = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
  if (simSuppressed) {
    unsigned char currentFlag = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
    savedProcessFlag = currentFlag;
  } else {
    savedProcessFlag = showCancel;
  }

  if (static_cast<short>(payloadResource) != 0) {
    overlaySfxIds[0] = 0xbcc;
    overlaySfxIds[1] = 0xbcd;
    overlaySfxIds[2] = 0xbce;
    overlaySfxIds[3] = 0xbcf;
    overlaySfxIds[4] = 0xbd0;
    overlaySfxIds[5] = static_cast<short>(g_overlaySfxSeasonWord + 0xbb8);
    overlaySfxIds[6] = 0xbd2;
    overlaySfxIds[7] = 0xbd3;
    overlaySfxIds[8] = 0xbd5;
    overlaySfxIds[9] = 0xbd6;
    overlaySfxIds[10] = 0xbd7;
    overlaySfxIds[11] = 0xbd7;
    overlaySfxIds[12] = 0xbd9;
    g_pSfxPlaybackSystem->PlaySoundEffect(overlaySfxIds[messageKind], 0, 1);
  }

  int modalResult = dialog->PoseModally();
  dialog->Close();
  dialog->Free();
  simSuppressed = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
  if (simSuppressed) {
    g_pGameFlowState->processPrimaryEventQueue = savedProcessFlag;
  }
  if (modalResult == kControlTagCncl) { // 'cncl'
    return false;
  }
  return true;
}

static void InitializeGameSetupFromDefaultNationPolicies(GameSetup* setup) {
  short* destination = setup->cityMinisterPolicyIds;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    destination[-7] = g_aDefaultNationSetupPolicyProfiles[nationSlot][0];
    destination[0] = g_aDefaultNationSetupPolicyProfiles[nationSlot][1];
    destination[kMajorNationCount] = g_aDefaultNationSetupPolicyProfiles[nationSlot][2];
    destination[0xe] = g_aDefaultNationSetupPolicyProfiles[nationSlot][3];
    ++destination;
  }
}

// FUNCTION: IMPERIALISM 0x005d6480
void TViewMgr::BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg) {
  CString messageText;    // composed modal body (chars/length are passed to the modal)
  CString nationNameText; // cases 6/0xa: the nation/terrain overlay label
  CString cityNameText;   // cases 3/4: the city display name
  CString templateText;   // bracket-template source for the scanBracket cases
  short resourceId;
  int dialogContext = 0;

  switch (overlayMode) {
  case 0: {
    CString seasonText;
    g_pSimMgr->GetString(0x273a, 0, &templateText);
    g_pSimMgr->GetString(0x2716, contextArg, &seasonText);
    scanBracketExpressions(g_pSimMgr, &messageText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(seasonText));
    dialogContext = 1;
    if (contextArg == 8) {
      resourceId = 0x2515;
    } else if (contextArg == 9) {
      resourceId = 0x2516;
    } else {
      resourceId = (contextArg != 0xc) ? 0x2508 : 0x2517;
    }
    break;
  }
  case 1: {
    g_pSimMgr->GetString(0x273a, 1, &messageText);
    dialogContext = 1;
    short nationId = g_pSimMgr->GetPlayerCountry();
    int cap = g_pTechMgr->nationCapRows1e8[nationId].slots[9];
    if (cap == 0x1c) {
      resourceId = 0x2518;
    } else {
      resourceId = (cap != 0x1d) ? 0x2509 : 0x2519;
    }
    break;
  }
  case 5:
  case 0xc:
    g_pSimMgr->GetString(0x273a, overlayMode, &messageText);
    dialogContext = 1;
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 6:
    g_apTerrainTypeDescriptorTable[contextArg]->GetName(&nationNameText);
    g_pSimMgr->GetString(0x273a, 6, &templateText);
    scanBracketExpressions(g_pSimMgr, &messageText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationNameText));
    dialogContext = 1;
    resourceId = 0x250e;
    break;
  case 0xa:
    g_apTerrainTypeDescriptorTable[contextArg]->FormatOverlayTerrainLabelText(&nationNameText);
    g_pSimMgr->GetString(0x273a, 0xa, &templateText);
    scanBracketExpressions(g_pSimMgr, &messageText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationNameText));
    dialogContext = 1;
    resourceId = 0x2512;
    break;
  case 2:
    g_pSimMgr->GetString(0x273a, 2, &messageText);
    resourceId = 0x250a;
    break;
  case 9:
  case 0xb:
    g_pSimMgr->GetString(0x273a, overlayMode, &messageText);
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 3:
  case 4:
    g_pGlobalMapState->AssignCityRecordDisplayName(contextArg, &cityNameText);
    g_pSimMgr->GetString(0x273a, overlayMode, &templateText);
    scanBracketExpressions(g_pSimMgr, &messageText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(cityNameText));
    dialogContext = 2;
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 7:
    g_pSimMgr->GetString(0x273a, 7, &messageText);
    dialogContext = 2;
    resourceId = (contextArg != -1) ? 0x250f : 0x251a;
    break;
  case 8:
    g_pSimMgr->GetString(0x273a, 8, &messageText);
    dialogContext = 2;
    resourceId = 0x2510;
    break;
  default:
    dialogContext = contextArg;
    resourceId = static_cast<short>(contextArg);
    break;
  }

  POINT modalPosition;
  modalPosition.x = -1000;
  modalPosition.y = resourceId;
  RunNationInfoModalAndReturnNonCancel(overlayMode, CString(g_pNationInfoEmptyText),
                                       static_cast<LPCSTR>(messageText), messageText.GetLength(),
                                       modalPosition, dialogContext, 0);
}

// FUNCTION: IMPERIALISM 0x005d69b0
void TViewMgr::GetTopLeftFor(TView* dialogView, POINT* outPlacement) {
  CRect mainBounds;
  g_pDisplayMgr->activeDialog->GetFrame(&mainBounds);
  (void)mainBounds; // original makes the call but discards the result

  CIncludeView* mainView = GetMainViewHostFromActiveThread();
  RECT clientRect;
  GetClientRect(mainView->m_hWnd, &clientRect);

  CRect dialogBounds;
  dialogView->GetFrame(&dialogBounds);
  int dlgWidth = dialogBounds.right - dialogBounds.left;
  int dlgHeight = dialogBounds.bottom - dialogBounds.top;

  int designWidth = 0x276;
  int designHeight = 0x1d1;
  int margin = 0x1e;
  short code = currentTurnEventCode;
  if (code == kTurnEventCitySiteSelector || code == kTurnEventStrategicMap) {
    designWidth = 0x200;
    designHeight = 0x1c0;
    margin = 0x16;
  } else if ((code >= kTurnEventDiplomacyMap && code <= kTurnEventCityProduction) ||
             code == kTurnEventTransport || code == kTurnEventTechnologyAdvance ||
             code == kTurnEventTacticalStatusRefresh || code == kTurnEventTacticalView ||
             code == kTurnEventOfferSheet || code == kTurnEventDealBook) {
    designHeight = 0x1c0;
  }

  outPlacement->x = (designWidth - dlgWidth) / 2 + clientRect.left + 5;
  outPlacement->y = (designHeight - dlgHeight) / 2 + clientRect.top + margin;
}

// FUNCTION: IMPERIALISM 0x005d6b70
void TViewMgr::RefreshMainViewNationIndicatorForCurrentTurnEvent() {
  TView* mainView = g_pDisplayMgr->activeDialog;
  if (mainView == NULL) {
    return;
  }
  // Turn-event 0x7DD targets the 'trb1' toolbar tag; everything else the 'tool' tag.
  TControl* control;
  if (currentTurnEventCode == kTurnEventStrategicMap) {
    control = static_cast<TControl*>(mainView->FindSubView(kControlTagTbr1));
  } else {
    control = static_cast<TControl*>(mainView->FindSubView(kControlTagTool));
  }
  if (control != NULL) {
    static_cast<TToolBarCluster*>(control)->SetReadouts(g_pSimMgr->GetPlayerCountry());
  }
}

// FUNCTION: IMPERIALISM 0x005d6bf0
void TViewMgr::AddPendingTurnOverlayCode(int modeValue) {
  pendingTurnOverlayCode =
      static_cast<short>(pendingTurnOverlayCode + static_cast<short>(modeValue));
}

// FUNCTION: IMPERIALISM 0x005d6c10
short TViewMgr::GetPendingTurnOverlayCode() {
  return pendingTurnOverlayCode;
}

// FUNCTION: IMPERIALISM 0x005d6c30
void TViewMgr::RefreshStrategicMapStatusIconsForActiveNation() {
  TView* mainView = g_pDisplayMgr->activeDialog;
  for (short iconIndex = 0; iconIndex <= 0x11; ++iconIndex) {
    TView* control = mainView->FindSubView(g_strategicMapStatusIconTagTable[iconIndex]);
    if (control != NULL) {
      control->AssertValid();
      g_pMacViewMgr->GetTradeCluster(static_cast<TTradeCluster*>(control), iconIndex,
                                     currentTurnEventNationSlot);
    }
  }
  g_apNationStates[currentTurnEventNationSlot]->RememberTradeBids();
}

// FUNCTION: IMPERIALISM 0x005d6cd0
void TViewMgr::MakeRelationshipDialog(int dialogContext) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(dialogContext), 0));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x4ff);
  }
  TRelationshipDialog* dialog = static_cast<TRelationshipDialog*>(
      static_cast<TView*>(node->FindSubView(kControlTagDialog))); // 'DLOG'
  dialog->AssertValid();
  if (dialog != NULL) {
    dialog->StuffValues();
  }
  node->Open();
}

// FUNCTION: IMPERIALISM 0x005d6d70
void TViewMgr::MakeMinorsTradeBidsDialog(int dialogContext) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(dialogContext), 0));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x514);
  }
  TMinorTradeBidsDialog* dialog = static_cast<TMinorTradeBidsDialog*>(
      static_cast<TView*>(node->FindSubView(kControlTagDialog))); // 'DLOG'
  dialog->AssertValid();
  if (dialog != NULL) {
    dialog->StuffValues();
  }
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6e30
void TViewMgr::NoOpTurnEventStateVtableSlot8C(int arg) {}

// FUNCTION: IMPERIALISM 0x005d6e50
void TViewMgr::MakeMinorRelationshipDialog(int dialogContext) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(dialogContext), 0));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x535);
  }
  TMinorRelationshipDialog* dialog = static_cast<TMinorRelationshipDialog*>(
      static_cast<TView*>(node->FindSubView(kControlTagDialog))); // 'DLOG'
  dialog->AssertValid();
  if (dialog != NULL) {
    dialog->StuffValues();
  }
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6f10
void TViewMgr::MakeGPTreatyDialog(int dialogContext) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(dialogContext), 0));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x54e);
  }
  TGPTreatyDialog* dialog = static_cast<TGPTreatyDialog*>(
      static_cast<TView*>(node->FindSubView(kControlTagDialog))); // 'DLOG'
  dialog->AssertValid();
  if (dialog != NULL) {
    dialog->StuffValues();
  }
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6fd0
void TViewMgr::MakeMinorTreatyDialog(int dialogContext) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(dialogContext), 0));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x566);
  }
  TMinorTreatyDialog* dialog = static_cast<TMinorTreatyDialog*>(
      static_cast<TView*>(node->FindSubView(kControlTagDialog))); // 'DLOG'
  dialog->AssertValid();
  if (dialog != NULL) {
    dialog->StuffValues();
  }
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d7090
bool TViewMgr::MakeDiplomacyOfferDialog(short sourceNation, short targetNation,
                                        short proposalCode) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), sourceNation);
  TDiplomacyMapView* mainView =
      static_cast<TDiplomacyMapView*>(activeDialog->FindSubView(kControlTagMain));
  mainView->AssertValid();
  mainView->PoseOffer(sourceNation, targetNation, proposalCode);
  return false;
}

// FUNCTION: IMPERIALISM 0x005d7100
char TViewMgr::MakeWarOfferDialog(int sourceNation, int minorNationSlot, int enemyNationSlot,
                                  int promptCode) {
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return 1;
  }
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), sourceNation);
  TDiplomacyMapView* mainView =
      static_cast<TDiplomacyMapView*>(activeDialog->FindSubView(kControlTagMain));
  mainView->AssertValid();
  return mainView->PoseWarOffer(static_cast<short>(sourceNation), minorNationSlot, enemyNationSlot,
                                promptCode);
}

// FUNCTION: IMPERIALISM 0x005d7190
void TViewMgr::NoOpTurnEventStateVtableSlotD4(int arg) {}

static void ClearMainViewChildWindowStyle(TView* mainView) {
  if (mainView->nativeWindow != NULL) {
    mainView->nativeWindow->ModifyStyle(0, 0x02000000);
  }
}

namespace turn_event_ui_refresh {

inline void BindCursorPanelAndStampDiplomacyMapTerrain(TView* mainView, short terrainIndex);

} // namespace turn_event_ui_refresh

static void DispatchPostTurnStateUpdatesTail(TurnEventCodeStorage eventCode) {
  if (g_pHelpMgr != NULL && !IsTurnFlowCooldownActiveAndResetExpiredState()) {
    g_pHelpMgr->HandlePostDispatchTurnStateEventUpdates();
    g_pHelpMgr->CheckHelp(eventCode);
    g_pHelpMgr->HandlePostPendingEventActivationNoOp(eventCode);
  }
}

// FUNCTION: IMPERIALISM 0x005d71b0
void TViewMgr::ShowOfferSheet(short respondingNation, short offeringNation, short proposedAmount,
                              short maxAmount, short commodityType) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TOfferDeskPicture* mainControl =
      static_cast<TOfferDeskPicture*>(activeDialog->FindSubView(kControlTagMain));
  mainControl->AssertValid();
  if (mainControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0x5c7);
  }
  mainControl->PoseOfferSheet(respondingNation, offeringNation, proposedAmount, maxAmount,
                              commodityType);
}

// FUNCTION: IMPERIALISM 0x005d7240
void TViewMgr::DispatchTurnEvent(TurnEventCodeStorage eventCode, int payload) {
  CPoint anchorPoint(dialogPlacement);
  TView* mainView = g_pDisplayMgr->activeDialog;
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  const TurnEventCodeStorage newCode = eventCode;
  const short secondary = payload;

  // Sound cue when the turn-flow mode is in the 0x67..0x6a band and the code changed.
  if (newCode != currentTurnEventCode) {
    switch (static_cast<short>(g_pSimMgr->mode)) {
    case kGamePhaseOptionalTradeOverview:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5b);
      break;
    case kGamePhaseOptionalDiplomacyMap:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5c);
      break;
    case kGamePhaseOptionalTransport:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5e);
      break;
    case kGamePhaseOptionalCityScreen:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5d);
      break;
    }
  }

  // Teardown hook for the code currently displayed.
  const int curCode = currentTurnEventCode;
  if (curCode < 0x2135) {
    if (curCode == kTurnEventOfferSheet) {
      ClearMainViewChildWindowStyle(mainView);
    } else {
      switch (curCode) {
      case kTurnEventTradeOverview:
      case kTurnEventIndustryOverview:
        RefreshStrategicMapStatusIconsForActiveNation();
        break;
      case kTurnEventCityProduction:
        g_pMacViewMgr->ClearActiveCityProductionViewAndDiscardRegion();
        break;
      case kTurnEventStrategicMap:
        mapUberPicture = 0;
        break;
      }
    }
  }

  // Code 0 = rebuild every registered UI window node.
  if (newCode == 0) {
    g_pAmbitApplication->dispatchBusyFlag = false;
    currentTurnEventCode = 0;
    g_pDisplayMgr->clipSnapshotEvent = 0;
    mainView->Close();
    CWMgrIterator iter;
    iter.Reset(true);
    TWindow* window = static_cast<TWindow*>(iter.FirstWindow());
    while (iter.More() != 0) {
      const unsigned int tag = window->controlTag;
      if (tag == kControlTagMapW || tag == kControlTagTrnW) {
        window->CloseAndFree();
      }
      window = static_cast<TWindow*>(iter.NextWindow());
    }
    return;
  }

  // Same-code refresh: refresh the main view, then run the per-code hook.
  if (newCode == currentTurnEventCode) {
    if (secondary != -1) {
      currentTurnEventNationSlot = secondary;
    }
    if (newCode == kTurnEventNetworkGameOptions) {
      QueueDeferredUiEventPacket(mainView, 0x29a, mainView);
    } else if (newCode == kTurnEventBattleReport) {
      mainView->RefreshControl();
      turn_event_ui_refresh::BindCursorPanelAndStampDiplomacyMapTerrain(mainView, secondary);
    } else if (newCode == kTurnEventTechnologyStore) {
      mainView->RefreshControl();
      RefreshTechnologyStorePageAndHudText(payload);
    } else if (newCode == kTurnEventDiplomacyMap) {
      if (static_cast<short>(g_pSimMgr->mode) == kGamePhaseOptionalDiplomacyMap) {
        mainView->RefreshControl();
        ShowDiplomacyScreen(static_cast<short>(payload));
      }
    } else if (newCode == kTurnEventTradeOverview || newCode == kTurnEventIndustryOverview) {
      mainView->RefreshControl();
      RefreshTradeAndIndustryOverviewScreen(payload);
    } else if (newCode == kTurnEventCityProduction) {
      mainView->RefreshControl();
      ShowCityProductionView(static_cast<short>(payload));
    } else if (newCode == kTurnEventStrategicMap) {
      mainView->RefreshControl();
      ShowTerrainMap(static_cast<short>(payload));
    } else if (newCode == kTurnEventTransport) {
      mainView->RefreshControl();
      ShowTransportScreen(static_cast<short>(payload));
    } else if (newCode == kTurnEventNewspaperStatus) {
      ShowNewspaper(secondary);
    } else if (newCode == kTurnEventDealBook) {
      mainView->RefreshControl();
      ShowDealBookScreen(static_cast<short>(payload));
    }
    DispatchPostTurnStateUpdatesTail(newCode);
    return;
  }

  // Cross-code path: tear down the previous dialog, build the new turn-event UI packet.
  g_pAssetMgr->OpenFilesForView(newCode);
  mainView->Open();
  if (waitOverlayPending) {
    ShowBlockingWaitOverlayDialog();
    waitOverlayPending = false;
  }
  TControl* inclControl = static_cast<TControl*>(mainView->FindSubView(kControlTagIncl)); // 'Incl'
  if (inclControl != NULL) {
    inclControl->AssertValid();
    inclControl->RefreshControl();
    inclControl->Free();
  }
  if (newCode != kTurnEventTechnologyAdvance) {
    currentTurnEventNationSlot = secondary;
  }

  TIncludeView* packet = ::new TIncludeView();
  CString emptyText(g_szEmptyString);
  packet->IIncludeView(NULL, mainView, newCode, anchorPoint, &emptyText, 1);
  packet->DoPostCreate(0);
  packet->controlTag = kControlTagIncl; // 'Incl'
  packet->RefreshControl();
  g_pDisplayMgr->UpdateTheGWorld(newCode);
  if (waitOverlayPending) {
    ShowBlockingWaitOverlayDialog();
    waitOverlayPending = false;
  }
  currentTurnEventCode = newCode;

  bool clearDispatchBusyFlag = true;

  if (newCode > kTurnEventMapEditor) {
    if (newCode < kTurnEventRandomGameSetup) {
      if (newCode == kTurnEventMainMenu) {
        SetUpMainMenuScreen();
      } else if (newCode == kTurnEventBattleReport) {
        turn_event_ui_refresh::BindCursorPanelAndStampDiplomacyMapTerrain(mainView, secondary);
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
      }
    } else if (newCode < kTurnEventTradeOverview) {
      switch (newCode) {
      case kTurnEventRandomGameSetup:
        NoOpTurnEventStateVtableSlotFC();
        break;
      case kTurnEventLoadSave:
        ShowLoadSaveScreen();
        break;
      case kTurnEventScenarioGameSetup:
        ShowScenarioScreen();
        break;
      case kTurnEventHighScores:
        ShowHighScoreScreen();
        break;
      case kTurnEventDiplomacyMap:
        ShowDiplomacyScreen(static_cast<short>(payload));
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
        break;
      }
    } else if (newCode > kTurnEventTechnologyAdvance) {
      if (newCode == kTurnEventTacticalView || newCode == kTurnEventTacticalStatusRefresh) {
        SyncTacticalStatusPanelRegion();
      } else if (newCode == kTurnEventTechnologyStore) {
        RefreshTechnologyStorePageAndHudText(payload);
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
      } else if (newCode == kTurnEventOpeningCinematic) {
        StartPhaseMovie();
      } else if (newCode == kTurnEventUnitHistory) {
        ShowUnitHistory(payload);
        clearDispatchBusyFlag = false;
      } else if (newCode == kTurnEventNewspaperStatus) {
        ShowNewspaper(secondary);
      } else if (newCode == kTurnEventOfferSheet) {
        RefreshMainDialogAndCursorHelp(payload);
      } else if (newCode == kTurnEventDealBook) {
        ShowDealBookScreen(static_cast<short>(payload));
      }
    } else if (newCode == kTurnEventTechnologyAdvance) {
      ShowAbilityStatusReport(payload);
    } else {
      switch (newCode) {
      case kTurnEventTradeOverview:
      case kTurnEventIndustryOverview:
        RefreshTradeAndIndustryOverviewScreen(payload);
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
        break;
      case kTurnEventCityProduction:
        ShowCityProductionView(static_cast<short>(payload));
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
        break;
      case kTurnEventStrategicMap:
        ShowTerrainMap(static_cast<short>(payload));
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
        break;
      case kTurnEventTransport:
        ShowTransportScreen(static_cast<short>(payload));
        g_pAmbitApplication->dispatchBusyFlag = true;
        clearDispatchBusyFlag = false;
        break;
      case kTurnEventCouncilOfGovernors:
        SetCursorRangeAndRefreshMainPanel(payload);
        break;
      }
    }
  } else if (newCode == kTurnEventMapEditor) {
    ConfigureMapEditorGoldValueGrid();
  } else if (newCode == kTurnEventCitySiteSelector) {
    InitializeCitySiteSelectionScreenForNation(payload);
  }
  if (clearDispatchBusyFlag) {
    g_pAmbitApplication->dispatchBusyFlag = false;
  }
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTestDriver::ObserveActivatedTurnEvent(newCode);
#endif
  DispatchPostTurnStateUpdatesTail(newCode);
}

// FUNCTION: IMPERIALISM 0x005d7c40
void TViewMgr::ShowCitySiteSelectorAndWait(int payload, TEventHandler* waitTarget) {
  DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCitySiteSelector), payload);
  while (static_cast<short>(waitTarget->lastIdleTick) == 0) {
    if (PumpUiMessagesAndBackgroundTasks(1) == 0) {
      g_pAmbitApplication->PostWmCloseToMainThreadWindow();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005d7cb0
void TViewMgr::ShowCityProductionView(short nationSlot) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  CString hoverText;
  g_pSimMgr->SetFlags(0x10);

  TInfoBarText* cursor = static_cast<TInfoBarText*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel = cursor;
  cursor->AssertValid();
  cursor->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TControl* cityControl = static_cast<TControl*>(mainView->FindSubView(kControlTagCity));
  if (cityControl != NULL) {
    TPicture* cityPicture = static_cast<TPicture*>(cityControl);
    cityPicture->SetPictureRsrcID(cityPicture->glyphBase + 1, 0);
    cityControl->ViewEnable(0, 0);
    g_pSimMgr->GetString(0x2730, 0x1d, &hoverText);
    SetControlHoverHelpTextAltEntry(hoverText, cityControl);
  }

  TToolBarCluster* topBar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTopB));
  topBar->AssertValid();
  topBar->AddInfoBehaviors();

  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTool));
  toolbar->AssertValid();
  toolbar->SetReadouts(nationSlot);
  toolbar->AddInfoBehaviors();

  TControl* querControl = static_cast<TControl*>(mainView->FindSubView(kControlTagQuer));
  if (querControl != NULL) {
    g_pSimMgr->GetString(0x2730, 2, &hoverText);
    SetControlHoverHelpText(hoverText, querControl);
  }

  TCityProductionView* productionView =
      static_cast<TCityProductionView*>(mainView->FindSubView(kControlTagMain));
  productionView->AssertValid();
  hoverText = CString(g_szEmptyString);
  SetControlHoverHelpText(hoverText, productionView);

  productionView = static_cast<TCityProductionView*>(mainView->FindSubView(kControlTagMain));
  productionView->AssertValid();
  g_pMacViewMgr->activeCityProductionView = productionView;

  TGreatPower* nation = g_apNationStates[nationSlot];
  TCity* city = nation != NULL ? nation->city : NULL;
  productionView->InitializeCityProductionDialog(city, mainView);
}

// FUNCTION: IMPERIALISM 0x005d7f70
void TViewMgr::UpdateCityScreen() {
  g_pMacViewMgr->UpdateCityScreen();
}

// FUNCTION: IMPERIALISM 0x005d7f90
void TViewMgr::CloseBuilding(short buildingSlot) {
  g_pMacViewMgr->CloseBuilding(buildingSlot);
}

// FUNCTION: IMPERIALISM 0x005d7fc0
void TViewMgr::SetCursorRangeAndRefreshMainPanel(int payload) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  TControl* cursor = static_cast<TControl*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel = static_cast<TInfoBarText*>(cursor);
  cursor->AssertValid();
  static_cast<TInfoBarText*>(cursor)->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
  TControl* mainPanel = static_cast<TControl*>(mainView->FindSubView(kControlTagMain));
  mainPanel->AssertValid();
  static_cast<TCouncilView*>(static_cast<void*>(mainPanel))->StartVoting();
}

// FUNCTION: IMPERIALISM 0x005d8040
void TViewMgr::ShowDiplomacyScreen(short nationSlot) {
  CString text;
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  g_pSimMgr->SetFlags(1);

  TInfoBarText* cursor = static_cast<TInfoBarText*>(activeDialog->FindSubView(kControlTagCurs));
  g_pCursorControlPanel = cursor;
  cursor->AssertValid();
  cursor->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TControl* diplControl = static_cast<TControl*>(activeDialog->FindSubView(kControlTagDipl));
  if (diplControl != NULL) {
    diplControl->AssertValid();
    TPicture* diplPicture = static_cast<TPicture*>(diplControl);
    diplPicture->SetPictureRsrcID(static_cast<short>(diplPicture->glyphBase + 1), 0);
    diplControl->ViewEnable(0, 0);
    g_pSimMgr->GetString(0x2730, 0x1c, &text);
    SetControlHoverHelpTextAltEntry(text, diplControl);
  }

  TToolBarCluster* topBar =
      static_cast<TToolBarCluster*>(activeDialog->FindSubView(kControlTagTopB));
  if (topBar != NULL) {
    topBar->AddInfoBehaviors();
  }

  TToolBarCluster* toolBar =
      static_cast<TToolBarCluster*>(activeDialog->FindSubView(kControlTagTool));
  toolBar->AssertValid();
  toolBar->SetReadouts(nationSlot);
  toolBar->AddInfoBehaviors();

  TControl* querControl = static_cast<TControl*>(activeDialog->FindSubView(kControlTagQuer));
  if (querControl != NULL) {
    g_pSimMgr->GetString(0x2730, 2, &text);
    SetControlHoverHelpText(text, querControl);
  }

  TView* diplomacyMap = activeDialog->FindSubView(kControlTagMain);
  diplomacyMap->AssertValid();
  SetControlHoverHelpText(CString(g_szEmptyString), diplomacyMap);

  if (topBar != NULL) {
    int grantSum = g_apNationStates[nationSlot]->SumDiplomacyGrantEntriesMaskedToValueBits();
    topBar->UpdateGrantDisplay(grantSum);
  }

  diplomacyMap = activeDialog->FindSubView(kControlTagMain);
  if (diplomacyMap != NULL && diplomacyMap->IsKindOf(RUNTIME_CLASS(TDiplomacyMapView)) != 0) {
    static_cast<TDiplomacyMapView*>(diplomacyMap)->SetSelectedTerrainIndexForTurnEvent(nationSlot);
  }
}

inline void turn_event_ui_refresh::BindCursorPanelAndStampDiplomacyMapTerrain(TView* mainView,
                                                                              short terrainIndex) {
  TControl* cursor = static_cast<TControl*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel = static_cast<TInfoBarText*>(cursor);
  cursor->AssertValid();
  static_cast<TInfoBarText*>(cursor)->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TView* diplomacyMap = mainView->FindSubView(kControlTagMain);
  diplomacyMap->AssertValid();
  if (diplomacyMap != NULL && diplomacyMap->IsKindOf(RUNTIME_CLASS(TDiplomacyMapView)) != 0) {
    static_cast<TDiplomacyMapView*>(diplomacyMap)
        ->SetSelectedTerrainIndexForTurnEvent(terrainIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005d83b0
void TViewMgr::ShowTransportScreen(short nationSlot) {
  CString text;

  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TView* hostView = activeDialog->FindSubView(kControlTagMain);
  hostView->AssertValid();
  hostView->RefreshControl();

  g_pSimMgr->SetFlags(0x1000);

  TInfoBarText* cursor = static_cast<TInfoBarText*>(activeDialog->FindSubView(kControlTagCurs));
  g_pCursorControlPanel = cursor;
  cursor->AssertValid();
  cursor->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TUpDownPictureButton* transportButton =
      static_cast<TUpDownPictureButton*>(activeDialog->FindSubView(kControlTagTran));
  if (transportButton != NULL) {
    transportButton->SetPictureRsrcID(static_cast<short>(transportButton->glyphBase + 1), 0);
    transportButton->ViewEnable(0, 0);
    g_pSimMgr->GetString(0x2730, 0x1e, &text);
    SetControlHoverHelpTextAltEntry(text, transportButton);
  }

  TToolBarCluster* topBar =
      static_cast<TToolBarCluster*>(activeDialog->FindSubView(kControlTagTopB));
  topBar->AssertValid();
  topBar->AddInfoBehaviors();

  TToolBarCluster* toolBar =
      static_cast<TToolBarCluster*>(activeDialog->FindSubView(kControlTagTool));
  toolBar->AssertValid();
  toolBar->SetReadouts(nationSlot);
  toolBar->AddInfoBehaviors();

  TView* queryControl = activeDialog->FindSubView(kControlTagQuer);
  if (queryControl != NULL) {
    g_pSimMgr->GetString(0x2730, 2, &text);
    SetControlHoverHelpText(text, queryControl);
  }

  {
    CString clearText(g_szEmptyString);
    text = clearText;
  }
  SetControlHoverHelpText(text, hostView);

  TDropShadowText* leftTitle =
      static_cast<TDropShadowText*>(hostView->FindSubView(kControlTagTitL));
  leftTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(leftTitle, 0, 0x12, 0x2b6b, 0x2b6c);
  g_pSimMgr->GetString(0x2735, 5, &text);
  leftTitle->SetTextAndMaybeRefresh(&text, false);

  TDropShadowText* rightTitle =
      static_cast<TDropShadowText*>(hostView->FindSubView(kControlTagTitR));
  rightTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(rightTitle, 0, 0x12, 0x2b6b, 0x2b6c);
  g_pSimMgr->GetString(0x2735, 6, &text);
  rightTitle->SetTextAndMaybeRefresh(&text, false);

  g_pMacViewMgr->ShowTransportEntry(-1, nationSlot, hostView);
  for (short row = 0; row < 0x17; ++row) {
    g_pMacViewMgr->ShowTransportEntry(row, nationSlot, hostView);
  }
}

// FUNCTION: IMPERIALISM 0x005d8750
void TViewMgr::RefreshTechnologyStorePageAndHudText(int nationSlot) {
  TView* mainView = g_pDisplayMgr->activeDialog;

  TTechStorePage* page = static_cast<TTechStorePage*>(mainView->FindSubView(kControlTagPage));
  page->AssertValid();
  page->StuffValues(nationSlot);

  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTool));
  toolbar->AssertValid();
  toolbar->SetReadouts(g_pSimMgr->GetPlayerCountry());
  toolbar->AddInfoBehaviors();

  g_pCursorControlPanel = static_cast<TInfoBarText*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  toolbar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTopB));
  toolbar->AssertValid();
  toolbar->AddInfoBehaviors();

  for (int titleIndex = 0; titleIndex < 3; ++titleIndex) {
    CString title;
    TDropShadowText* titleControl = static_cast<TDropShadowText*>(
        mainView->FindSubView(kControlTagTtl1 + titleIndex)); // 'ttl1'..'ttl3'
    titleControl->AssertValid();
    ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0xe, 0x2b6a, 0x2b68);
    g_pSimMgr->GetString(0x274f, static_cast<short>(titleIndex + 4), &title);
    titleControl->SetTextAndMaybeRefresh(&title, true);
  }

  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagPage);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 0xd, kControlTagEnd);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 3, kControlTagQuer);
}

// FUNCTION: IMPERIALISM 0x005d8980
void TViewMgr::ShowAbilityStatusReport(short abilityIndex) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TextStyle style;
  style.textColor = 0;
  CString statusText;
  CString prefix;
  TPicture* mainControl = static_cast<TPicture*>(activeDialog->FindSubView(kControlTagMain));
  mainControl->AssertValid();

  TControl* queryControl = static_cast<TControl*>(activeDialog->FindSubView(kControlTagQuer));
  if (queryControl != 0) {
    g_pSimMgr->GetString(0x2730, 2, &statusText);
    SetControlHoverHelpText(statusText, queryControl);
  }

  TControl* toolControl = static_cast<TControl*>(activeDialog->FindSubView(kControlTagTool));
  toolControl->AssertValid();
  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(toolControl);
  toolbar->SetReadouts(g_pSimMgr->GetPlayerCountry());
  toolbar->AddInfoBehaviors();

  g_pCursorControlPanel = static_cast<TInfoBarText*>(activeDialog->FindSubView(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  short pictureResourceId = static_cast<short>(g_anAbilityStatusPictureIndex[abilityIndex] + 0x897);
  mainControl->SetPictureRsrcID(pictureResourceId, true);

  TDeluxeText* textControl = static_cast<TDeluxeText*>(activeDialog->FindSubView(kControlTagText));
  textControl->AssertValid();
  g_pSimMgr->GetString(0x274e, abilityIndex - 1, &prefix);
  g_pSimMgr->GetString(0x2712, abilityIndex, &statusText);
  statusText += '\r';
  statusText += '\r';
  statusText += prefix;
  textControl->SetTextAndMaybeRefresh(&statusText, true);

  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6b);
  textControl->InstallTextStyle(style, 0);
  textControl->SetJustification(-2, false);
  activeDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005d8c40
void TViewMgr::ShowNewspaper(int pageIndex) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TNewspaperView* mainControl =
      static_cast<TNewspaperView*>(activeDialog->FindSubView(kControlTagMain));
  mainControl->AssertValid();
  g_pSfxPlaybackSystem->PlaySoundEffect(0x14b4, 0, 1);
  mainControl->StuffValues(pageIndex);
  activeDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005d8cc0
void TViewMgr::SyncTacticalStatusPanelRegion() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CTemporaryRegion temporaryRegion;
  TTacticalBattleView* goldControl =
      static_cast<TTacticalBattleView*>(activeDialog->FindSubView(kControlTagDialog));
  goldControl->AssertValid();
  goldControl->SyncStatusPanelBounds();

  TOffLimitsPicture* owner = static_cast<TOffLimitsPicture*>(goldControl->ownerContext);
  owner->AssertValid();

  CRect bounds;
  goldControl->GetFrame(&bounds);
  RECT regionBounds = bounds;
  RectRgn(temporaryRegion.tempRgn, &regionBounds);

  owner->SetRgn(temporaryRegion.tempRgn);
}

// FUNCTION: IMPERIALISM 0x005d8dd0
void TViewMgr::RefreshTradeAndIndustryOverviewScreen(int nationIndex) {
  CString sharedString;
  TView* mainView = g_pDisplayMgr->activeDialog;
  g_pSimMgr->SetFlags(0x100);

  g_pCursorControlPanel = static_cast<TInfoBarText*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TUpDownPictureButton* tradeControl =
      static_cast<TUpDownPictureButton*>(mainView->FindSubView(kControlTagTrad));
  if (tradeControl != 0) {
    tradeControl->SetPictureRsrcID(static_cast<short>(tradeControl->glyphBase + 1), false);
    tradeControl->ViewEnable(0, 0);
    g_pSimMgr->GetString(0x2730, 0x1b, &sharedString);
    SetControlHoverHelpTextAltEntry(sharedString, tradeControl);
  }

  TToolBarCluster* topToolbar =
      static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTopB));
  topToolbar->AssertValid();
  topToolbar->AddInfoBehaviors();

  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTool));
  toolbar->AssertValid();
  toolbar->SetReadouts(nationIndex);
  toolbar->AddInfoBehaviors();

  TView* queryControl = mainView->FindSubView(kControlTagQuer);
  if (queryControl != 0) {
    g_pSimMgr->GetString(0x2730, 2, &sharedString);
    SetControlHoverHelpText(sharedString, queryControl);
  }

  TView* mainControl = mainView->FindSubView(kControlTagMain);
  mainControl->AssertValid();
  sharedString = CString(g_szEmptyString);
  SetControlHoverHelpText(sharedString, mainControl);

  short nationSlot = nationIndex;
  g_apNationStates[nationSlot]->RecallTradeBids();
  pendingTurnOverlayCode = 0;
  for (short metricSlot = 0; metricSlot < 0x11; ++metricSlot) {
    if (g_apNationStates[nationSlot]->GetTradeOffersFor(metricSlot) == -1) {
      pendingTurnOverlayCode = static_cast<short>(pendingTurnOverlayCode + 1);
    }
  }

  const unsigned int kTagTopTitle = IMPERIALISM_FOURCC('t', 'o', 'p', 'T');
  const unsigned int kTagCommodityTitle = IMPERIALISM_FOURCC('c', 'o', 'm', 'T');
  const unsigned int kTagOrdersTitle = IMPERIALISM_FOURCC('o', 'r', 'd', 'T');
  const unsigned int kTagPriceTitle = IMPERIALISM_FOURCC('p', 'r', 'i', 'T');
  const unsigned int kTagAvailableTitle = IMPERIALISM_FOURCC('a', 'v', 'a', 'T');
  const unsigned int kTagQuantityTitle = IMPERIALISM_FOURCC('q', 't', 'y', 'T');
  const unsigned int kTagMiniPicture = IMPERIALISM_FOURCC('m', 'P', 'i', 'c');

  TextStyle columnStyle = {0};
  TDropShadowText* title = static_cast<TDropShadowText*>(mainView->FindSubView(kTagTopTitle));
  title->AssertValid();
  ApplyUiTextStyleAndThemeFlags(title, 0, 0x10, 0x2b6c, 0x2b67);
  g_pSimMgr->GetString(0x2731, 0xc, &sharedString);
  title->SetTextAndMaybeRefresh(&sharedString, false);

  TDropShadowText* commodityTitle =
      static_cast<TDropShadowText*>(mainView->FindSubView(kTagCommodityTitle));
  commodityTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(commodityTitle, 0, 0xc, 0x2b6c, 0x2b67);
  g_pSimMgr->GetString(0x2731, 0, &sharedString);
  g_pSimMgr->GetString(0x2731, 0xd, &sharedString);
  commodityTitle->SetTextAndMaybeRefresh(&sharedString, false);

  TDropShadowText* ordersTitle =
      static_cast<TDropShadowText*>(mainView->FindSubView(kTagOrdersTitle));
  ordersTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(ordersTitle, 0, 0xc, 0x2b6c, 0x2b67);
  g_pSimMgr->GetString(0x2731, 0xe, &sharedString);
  ordersTitle->SetTextAndMaybeRefresh(&sharedString, false);

  BuildUiTextStyleDescriptor(&columnStyle, 0, 0xc, 0x2b68);
  TStaticText* priceTitle = static_cast<TStaticText*>(mainView->FindSubView(kTagPriceTitle));
  priceTitle->AssertValid();
  priceTitle->InstallTextStyle(columnStyle, 0);
  g_pSimMgr->GetString(0x2731, 0xf, &sharedString);
  priceTitle->SetTextAndMaybeRefresh(&sharedString, false);

  TStaticText* availableTitle =
      static_cast<TStaticText*>(mainView->FindSubView(kTagAvailableTitle));
  availableTitle->AssertValid();
  availableTitle->InstallTextStyle(columnStyle, 0);
  g_pSimMgr->GetString(0x2731, 0x10, &sharedString);
  availableTitle->SetTextAndMaybeRefresh(&sharedString, false);

  TStaticText* quantityTitle = static_cast<TStaticText*>(mainView->FindSubView(kTagQuantityTitle));
  quantityTitle->AssertValid();
  quantityTitle->InstallTextStyle(columnStyle, 0);
  g_pSimMgr->GetString(0x2731, 0x11, &sharedString);
  quantityTitle->SetTextAndMaybeRefresh(&sharedString, false);

  TView* miniPicture = mainView->FindSubView(kTagMiniPicture);
  miniPicture->AssertValid();
  g_pSimMgr->GetString(0x2731, 3, &sharedString);
  SetControlHoverHelpText(sharedString, miniPicture);

  TDropShadowNumberText* capacity =
      static_cast<TDropShadowNumberText*>(mainView->FindSubView(kControlTagMCap));
  if (capacity == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xa52);
  }
  ApplyUiNumberTextStyleAndThemeColor(capacity, 0, 0xa, 0x2b6c, 0x2b67);
  capacity->SetJustification(1, false);
  capacity->SetControlValue(g_apNationStates[nationSlot]->merchantCapacity, 0);

  TCity* city = g_apNationStates[nationSlot] == 0 ? 0 : g_apNationStates[nationSlot]->city;
  if (city == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xa5a);
  }
  short* citySummary = city->GetUnmetNeeds();

  const unsigned int kTagFood = IMPERIALISM_FOURCC('f', 'o', 'o', 'd');
  const unsigned int kTagCotton = IMPERIALISM_FOURCC('c', 'o', 't', 't');
  const unsigned int kTagWool = IMPERIALISM_FOURCC('w', 'o', 'o', 'l');
  const unsigned int kTagTimber = IMPERIALISM_FOURCC('t', 'i', 'm', 'b');
  const unsigned int kTagCoal = IMPERIALISM_FOURCC('c', 'o', 'a', 'l');
  const unsigned int kTagIron = IMPERIALISM_FOURCC('i', 'r', 'o', 'n');
  const unsigned int kTagOil = IMPERIALISM_FOURCC('o', 'i', 'l', ' ');
  const unsigned int kTagFabric = IMPERIALISM_FOURCC('f', 'a', 'b', 'r');
  const unsigned int kTagLumber = IMPERIALISM_FOURCC('l', 'u', 'm', 'b');
  const unsigned int kTagSteel = IMPERIALISM_FOURCC('s', 't', 'e', 'e');

  TView* food = mainView->FindSubView(kTagFood);
  if (food == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xa60);
  }
  const short foodOnHand =
      static_cast<short>(city->stockByType[kResourceFood] + city->stockByType[kResourceLivestock] +
                         city->stockByType[kResourceGrain] + city->stockByType[kResourceFruit] +
                         g_apNationStates[nationSlot]->needTargetByType[kResourceLivestock] +
                         g_apNationStates[nationSlot]->needTargetByType[kResourceFruit] +
                         g_apNationStates[nationSlot]->needTargetByType[kResourceFish] +
                         g_apNationStates[nationSlot]->needTargetByType[kResourceGrain]);
  const short foodRequired = static_cast<short>(
      citySummary[kResourceLivestock] + citySummary[kResourceFruit] + citySummary[kResourceGrain]);
  if (foodOnHand < foodRequired) {
    food->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 4, &sharedString);
  } else {
    food->Show(0, 0);
    g_pSimMgr->GetString(0x2731, 8, &sharedString);
  }
  SetControlHoverHelpText(sharedString, food);

  TView* cotton = mainView->FindSubView(kTagCotton);
  TView* wool = mainView->FindSubView(kTagWool);
  short textileNeeds =
      static_cast<short>(g_apNationStates[nationSlot]->needTargetByType[kResourceCotton] +
                         g_apNationStates[nationSlot]->needTargetByType[kResourceWool]);
  short textileStock =
      static_cast<short>(city->stockByType[kResourceWool] + city->stockByType[kResourceCotton]);
  if (static_cast<int>(textileStock) + static_cast<int>(textileNeeds) <
      static_cast<short>(city->GetBuildingType(0) << 1)) {
    cotton->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x13, &sharedString);
    SetControlHoverHelpText(sharedString, cotton);
    wool->Show(1, 0);
  } else {
    cotton->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
    SetControlHoverHelpText(sharedString, cotton);
    wool->Show(0, 0);
  }
  SetControlHoverHelpText(sharedString, wool);

  TView* timber = mainView->FindSubView(kTagTimber);
  if (static_cast<int>(city->stockByType[kResourceTimber]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceTimber]) <
      static_cast<short>(city->GetBuildingType(4) * 2)) {
    timber->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x15, &sharedString);
  } else {
    timber->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
  }
  SetControlHoverHelpText(sharedString, timber);

  TView* coal = mainView->FindSubView(kTagCoal);
  if (static_cast<int>(city->stockByType[kResourceCoal]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceCoal]) <
      city->GetBuildingType(2)) {
    coal->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x16, &sharedString);
  } else {
    coal->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
  }
  SetControlHoverHelpText(sharedString, coal);

  TView* iron = mainView->FindSubView(kTagIron);
  if (static_cast<int>(city->stockByType[kResourceIron]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceIron]) <
      city->GetBuildingType(2)) {
    iron->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x17, &sharedString);
  } else {
    iron->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
  }
  SetControlHoverHelpText(sharedString, iron);

  TView* oil = mainView->FindSubView(kTagOil);
  if (static_cast<int>(city->stockByType[kResourceOil]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceOil]) <
      static_cast<short>(city->GetBuildingType(6) * 2)) {
    oil->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x18, &sharedString);
  } else {
    oil->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
  }
  SetControlHoverHelpText(sharedString, oil);

  TView* fabric = mainView->FindSubView(kTagFabric);
  if (static_cast<int>(city->stockByType[kResourceFabric]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceFabric]) <
      static_cast<short>(city->GetBuildingType(1) * 2)) {
    fabric->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x19, &sharedString);
  } else {
    fabric->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
  }
  SetControlHoverHelpText(sharedString, fabric);

  TView* lumber = mainView->FindSubView(kTagLumber);
  if (static_cast<int>(city->stockByType[kResourceLumber]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceLumber]) <
      static_cast<short>(city->GetBuildingType(5) * 2)) {
    lumber->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x1a, &sharedString);
  } else {
    lumber->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
  }
  SetControlHoverHelpText(sharedString, lumber);

  TView* steel = mainView->FindSubView(kTagSteel);
  if (static_cast<int>(city->stockByType[kResourceSteel]) +
          static_cast<int>(g_apNationStates[nationSlot]->needTargetByType[kResourceSteel]) <
      static_cast<short>(city->GetBuildingType(3) * 2)) {
    steel->Show(1, 0);
    g_pSimMgr->GetString(0x2731, 0x1b, &sharedString);
    SetControlHoverHelpText(sharedString, steel);
  } else {
    steel->Show(0, 0);
    sharedString = CString(g_pNationInfoEmptyText);
    SetControlHoverHelpText(sharedString, steel);
  }
  SetControlHoverHelpText(sharedString, steel);

  if (g_apNationStates[nationSlot]->merchantCapacity == 0) {
    g_pSimMgr->GetString(0x2731, 0x12, &sharedString);
    g_pViewMgr->ModalMessage(sharedString, g_ptCitySiteSelectionDialogPlacement);
    pendingTurnOverlayCode = 5;
  }

  for (short commodity = 0; commodity < 0x11; ++commodity) {
    TView* row = mainView->FindSubView(g_strategicMapStatusIconTagTable[commodity]);
    if (row == NULL) {
      continue;
    }
    g_pMacViewMgr->ShowTradeCluster(row, commodity, static_cast<short>(nationIndex));
    if ((commodity == 6 || commodity == 0xc) &&
        g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] == 0) {
      row->Free();
    } else {
      g_pSimMgr->GetCommodityName(commodity, &sharedString);
      SetControlHoverHelpText(sharedString, row);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005da040
void TViewMgr::RefreshMainDialogAndCursorHelp(int) {
  TView* mainControl =
      static_cast<TView*>(g_pDisplayMgr->activeDialog->FindSubView(kControlTagMain));
  mainControl->AssertValid();
  mainControl->RefreshControl();

  g_pCursorControlPanel = static_cast<TInfoBarText*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->FindSubView(kControlTagCurs)));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  CString emptyTitle(g_szEmptyString);
  SetControlHoverHelpText(emptyTitle, mainControl);
}

// FUNCTION: IMPERIALISM 0x005da180
void TViewMgr::ShowDealBookScreen(short nationSlot) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  CString sharedString;

  g_pCursorControlPanel = static_cast<TInfoBarText*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TView* mainControl = static_cast<TView*>(mainView->FindSubView(kControlTagMain));
  mainControl->AssertValid();
  sharedString = CString(g_szEmptyString);
  SetControlHoverHelpText(sharedString, mainControl);

  TView* queryControl = mainControl->FindSubView(kControlTagQuer);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, queryControl);

  TDropShadowText* titleControl =
      static_cast<TDropShadowText*>(mainControl->FindSubView(kControlTagTitL)); // 'titL'
  titleControl->AssertValid();
  ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0x12, 0x2b6c, 0x2b6b);
  titleControl->SetJustification(1, false);
  g_pSimMgr->GetString(0x2741, 0, &sharedString);
  titleControl->SetTextAndMaybeRefresh(&sharedString, false);
  static_cast<TDealBookPicture*>(mainControl)->Startup(nationSlot);
}

// FUNCTION: IMPERIALISM 0x005da360
void TViewMgr::ShowTerrainMap(short nationSlot) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  CString sharedString;

  if (!g_pSimMgr->ReallyInTheGame(g_pSimMgr->GetPlayerCountry())) {
    g_pSimMgr->SetFlags(static_cast<unsigned int>(-1));
  }

  TInfoBarText* cursorPanel = static_cast<TInfoBarText*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel = cursorPanel;
  cursorPanel->AssertValid();
  cursorPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TToolBarCluster* toolBar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTbr1));
  toolBar->AssertValid();
  toolBar->SetReadouts(nationSlot);
  toolBar->AddInfoBehaviors();

  toolBar = static_cast<TToolBarCluster*>(mainView->FindSubView(kControlTagTool));
  toolBar->AssertValid();
  toolBar->AddInfoBehaviors();

  TPicture* statusPicture = static_cast<TPicture*>(mainView->FindSubView(kControlTagDipl));
  statusPicture->AssertValid();
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(1)) {
    statusPicture->SetPictureRsrcID(0x24d9, 0);
  } else {
    statusPicture->SetPictureRsrcID(0x24e1, 0);
  }

  statusPicture = static_cast<TPicture*>(mainView->FindSubView(kControlTagTrad));
  statusPicture->AssertValid();
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x100)) {
    statusPicture->SetPictureRsrcID(0x24db, 0);
  } else {
    statusPicture->SetPictureRsrcID(0x24e3, 0);
  }

  statusPicture = static_cast<TPicture*>(mainView->FindSubView(kControlTagCity));
  statusPicture->AssertValid();
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x10)) {
    statusPicture->SetPictureRsrcID(0x24dd, 0);
  } else {
    statusPicture->SetPictureRsrcID(0x24e5, 0);
  }

  statusPicture = static_cast<TPicture*>(mainView->FindSubView(kControlTagTran));
  statusPicture->AssertValid();
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x1000)) {
    statusPicture->SetPictureRsrcID(0x24df, 0);
  } else {
    statusPicture->SetPictureRsrcID(0x24e7, 0);
  }

  statusPicture = static_cast<TPicture*>(mainView->FindSubView(kControlTagMmap));
  statusPicture->AssertValid();
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x40)) {
    statusPicture->SetPictureRsrcID(0x419, 0);
  } else {
    statusPicture->SetPictureRsrcID(0x24d7, 0);
  }

  TMapUberPicture* mapPicture =
      static_cast<TMapUberPicture*>(mainView->FindSubView(kControlTagMain));
  mapPicture->AssertValid();
  if (mapPicture == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc5a);
  }
  mapPicture->DisplayMiniMap();
  sharedString = g_szEmptyString;
  SetControlHoverHelpText(sharedString, mapPicture);
  mapUberPicture = mapPicture;

  TView* zoomControl = mainView->FindSubView(kControlTagZmOt);
  if (zoomControl == 0) {
    zoomControl = mainView->FindSubView(kControlTagZmIn);
    if (zoomControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc69);
    }
  }
  g_pSimMgr->GetString(0x2732, 5, &sharedString);
  SetControlHoverHelpText(sharedString, zoomControl);

  TView* miniMapControl = mainView->FindSubView(kControlTagMmap);
  if (miniMapControl == 0) {
    miniMapControl = mainView->FindSubView(kControlTagInfo);
    if (miniMapControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc70);
    }
  }
  g_pSimMgr->GetString(0x2732, 0xc, &sharedString);
  SetControlHoverHelpText(sharedString, miniMapControl);

  TView* orderControl = mainView->FindSubView(kControlTagTrad);
  if (orderControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc76);
  }
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x100)) {
    g_pSimMgr->GetString(0x2730, 0x13, &sharedString);
  } else {
    g_pSimMgr->GetString(0x2730, 0x17, &sharedString);
  }
  SetControlHoverHelpText(sharedString, orderControl);

  orderControl = mainView->FindSubView(kControlTagDipl);
  if (orderControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc7e);
  }
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(1)) {
    g_pSimMgr->GetString(0x2730, 0x14, &sharedString);
  } else {
    g_pSimMgr->GetString(0x2730, 0x18, &sharedString);
  }
  SetControlHoverHelpText(sharedString, orderControl);

  orderControl = mainView->FindSubView(kControlTagCity);
  if (orderControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc86);
  }
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x10)) {
    g_pSimMgr->GetString(0x2730, 0x15, &sharedString);
  } else {
    g_pSimMgr->GetString(0x2730, 0x19, &sharedString);
  }
  SetControlHoverHelpText(sharedString, orderControl);

  orderControl = mainView->FindSubView(kControlTagTran);
  if (orderControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xc8e);
  }
  if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x1000)) {
    g_pSimMgr->GetString(0x2730, 0x16, &sharedString);
  } else {
    g_pSimMgr->GetString(0x2730, 0x1a, &sharedString);
  }
  SetControlHoverHelpText(sharedString, orderControl);

  for (int rosterIndex = 0; rosterIndex < 3; rosterIndex++) {
    unsigned int rosterTag;
    if (rosterIndex == 0) {
      rosterTag = kControlTagUciv;
    } else if (rosterIndex == 1) {
      rosterTag = kControlTagUarm;
    } else {
      rosterTag = kControlTagUnav;
    }
    TView* roster = mainView->FindSubView(rosterTag);
    if (roster == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xca0);
    }
    TView* rosterHotspot = roster->FindSubView(rosterIndex < 2 ? kControlTagLatr : kControlTagNext);
    if (rosterHotspot == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xca6);
    }
    g_pSimMgr->GetString(0x2732, 0, &sharedString);
    SetControlHoverHelpText(sharedString, rosterHotspot);

    rosterHotspot = roster->FindSubView(kControlTagDfnd);
    if (rosterHotspot == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcab);
    }
    g_pSimMgr->GetString(0x2732, static_cast<short>(rosterIndex + 1), &sharedString);
    SetControlHoverHelpText(sharedString, rosterHotspot);

    rosterHotspot = roster->FindSubView(kControlTagDone);
    if (rosterHotspot == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcb0);
    }
    g_pSimMgr->GetString(0x2732, 4, &sharedString);
    SetControlHoverHelpText(sharedString, rosterHotspot);
  }

  TView* civRoster = mainView->FindSubView(kControlTagUciv);
  if (civRoster == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcb7);
  }
  TView* rosterChild = civRoster->FindSubView(kControlTagUnit);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcc2);
  }
  g_pSimMgr->GetString(0x2732, 0xe, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  rosterChild = civRoster->FindSubView(kControlTagBack);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcc8);
  }
  sharedString = g_szEmptyString;
  SetControlHoverHelpText(sharedString, rosterChild);

  rosterChild = civRoster->FindSubView(kControlTagGarr);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xccd);
  }
  g_pSimMgr->GetString(0x2732, 0xf, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  TView* armyRoster = mainView->FindSubView(kControlTagUarm);
  if (armyRoster == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcd3);
  }
  for (int placardIndex = 0; placardIndex < 10; placardIndex++) {
    TView* placard = armyRoster->FindSubView(kControlTagArmyPlacardFirst + placardIndex);
    if (placard == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcd9);
    }
    g_pSimMgr->GetString(0x2726, static_cast<short>(placardIndex), &sharedString);
    SetControlHoverHelpText(sharedString, placard);
  }
  rosterChild = armyRoster->FindSubView(kControlTagGarr);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcdf);
  }
  g_pSimMgr->GetString(0x2732, 7, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  TView* navyRoster = mainView->FindSubView(kControlTagUnav);
  if (navyRoster == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xce5);
  }
  rosterChild = navyRoster->FindSubView(kControlTagBack);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xce9);
  }
  sharedString = g_szEmptyString;
  SetControlHoverHelpText(sharedString, rosterChild);

  rosterChild = navyRoster->FindSubView(kControlTagBomb);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xcfe);
  }
  g_pSimMgr->GetString(0x2732, 8, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  rosterChild = navyRoster->FindSubView(kControlTagAgr0);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xd03);
  }
  g_pSimMgr->GetString(0x2732, 9, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  rosterChild = navyRoster->FindSubView(kControlTagAgr1);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xd08);
  }
  g_pSimMgr->GetString(0x2732, 0xa, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  rosterChild = navyRoster->FindSubView(kControlTagAgr2);
  if (rosterChild == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xd0d);
  }
  g_pSimMgr->GetString(0x2732, 0xb, &sharedString);
  SetControlHoverHelpText(sharedString, rosterChild);

  // The dialog root is only asserted; the map picture then re-arms its click selection.
  if (mapPicture->FindSubView(kControlTagDialog) == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xd17);
  }
  mapPicture->CycleMapInteractionSelectionAfterHandledClick();
}

// FUNCTION: IMPERIALISM 0x005db3b0
void TViewMgr::StartPhaseMovie() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TMovieView* movieView = static_cast<TMovieView*>(activeDialog->FindSubView(kControlTagMovi));
  movieView->AssertValid();
  movieView->ViewEnable(1, 0);
  movieView->ForceRedraw();

  CString movieName;
  switch (g_pSimMgr->mode) {
  case kGamePhaseStartup:
    movieName = CString("open");
    if (movieView->nextHandler != 0) {
      static_cast<TView*>(movieView->nextHandler)->ViewEnable(0, 0);
    }
    break;
  case kGamePhaseCouncil:
    movieName = CString("vote");
    break;
  case kGamePhaseCouncilVictory:
    movieName = CString("win");
    break;
  case kGamePhaseCouncilDefeat:
    movieName = CString("lose");
    break;
  case kGamePhaseEliminations:
    if (g_pSimMgr->ReallyInTheGame(g_pSimMgr->GetPlayerCountry())) {
      movieName = CString("win");
    } else {
      movieName = CString("lose");
    }
    break;
  default:
    movieName = CString("lose");
    break;
  }

  if (!movieName.IsEmpty()) {
    g_pAssetMgr->OpenMovie(movieName, movieView, 0);
  }
}

// FUNCTION: IMPERIALISM 0x005db620
void TViewMgr::HandleTurnStateExitAndPostFollowupEventCode(short followupState) {
  pendingFollowupState = followupState;
  if (followupState != 0) {
    return;
  }
  g_pSfxPlaybackSystem->RequestDirectSoundInitIfAllowed();
  g_pSfxPlaybackSystem->SetMasterVolumeFromPercent(g_pSimMgr->preferenceValues[2]);
  g_pSfxPlaybackSystem->ScaleAndApplyAuxOutputVolume(g_pSimMgr->preferenceValues[3]);
  activeMovieView = 0;
  switch (g_pSimMgr->mode) {
  case kGamePhaseStartup:
    g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventMainMenu));
    return;
  case kGamePhaseCouncil:
  case kGamePhaseCouncilVictory:
  case kGamePhaseCouncilDefeat:
    g_pAmbitApplication->PostTurnEventCodeMessage(
        EncodeTurnEventCode(kTurnEventCouncilOfGovernors));
    return;
  case kGamePhaseEliminations:
    if (g_pSimMgr->ReallyInTheGame(g_pSimMgr->GetPlayerCountry())) {
      g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventGameScore));
      return;
    }
  default:
    ReinitializeGameFlowAndPostTurnEventCode(kTurnEventRebuildRegisteredWindows);
  }
}

static void RefreshMainMenuButtonLabel(TView* mainView, unsigned int controlTag, short codeGroup,
                                       short stringIndex, int assertLine, CString* label) {
  TControl* control = static_cast<TControl*>(mainView->FindSubView(controlTag));
  if (control == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, assertLine);
  }
  g_pSimMgr->GetString(codeGroup, stringIndex, label);
  control->SetHoverHelpText(*label);
}

// FUNCTION: IMPERIALISM 0x005db780
void TViewMgr::SetUpMainMenuScreen() {
  TView* mainView = g_pDisplayMgr->activeDialog;

  g_pSfxPlaybackSystem->ResetPlayList();
  g_pSfxPlaybackSystem->AddToPlayList(6);
  g_pSfxPlaybackSystem->PlayRandomTrack();

  g_pCursorControlPanel = NULL;
  g_pCursorControlPanel = static_cast<TInfoBarText*>(mainView->FindSubView(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();

  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);

  TextStyle styleDescriptor = {0, 0, 0, 0};
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xe, 0x2b6c);
  g_pCursorControlPanel->SetTextStyle(styleDescriptor, true);
  g_pCursorControlPanel->SetJustification(1, false);

  COLORREF mappedStyleFlags = 0;
  ResolveUiThemeColor(0x2b6b, &mappedStyleFlags);
  g_pCursorControlPanel->shadowTextColor = mappedStyleFlags;
  g_pCursorControlPanel->dropShadowEnabled = true;

  // 'main' (council ticker) is not null-checked in the original, unlike the buttons below.
  TControl* mainControl = static_cast<TControl*>(mainView->FindSubView(kControlTagMain));
  mainControl->AssertValid();
  CString emptyString(g_szEmptyString);
  mainControl->SetHoverHelpText(emptyString);

  CString label;
  RefreshMainMenuButtonLabel(mainView, kControlTagRand, 0x2737, 0, 0xdf0, &label);
  RefreshMainMenuButtonLabel(mainView, kControlTagLoad, 0x2737, 1, 0xdf9, &label);
  RefreshMainMenuButtonLabel(mainView, kControlTagMult, 0x2737, 2, 0xdfe, &label);
  RefreshMainMenuButtonLabel(mainView, kControlTagHigh, 0x2737, 3, 0xe03, &label);
  RefreshMainMenuButtonLabel(mainView, kControlTagScen, 0x2737, 4, 0xe08, &label);
  RefreshMainMenuButtonLabel(mainView, kControlTagQuit, 0x2737, 9, 0xe0d, &label);
  RefreshMainMenuButtonLabel(mainView, kControlTagPref, 0x2743, 8, 0xe12, &label);
}

// FUNCTION: IMPERIALISM 0x005dbd10
void TViewMgr::NoOpTurnEventStateVtableSlotFC() {}

// FUNCTION: IMPERIALISM 0x005dbd30
void TViewMgr::ShowLoadSaveScreen() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CString scratch;
  TView* mainView = activeDialog->FindSubView(kControlTagMain);
  mainView->AssertValid();
  mainView->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005dbdd0
void TViewMgr::ShowScenarioScreen() {
  TView* mainPanel = g_pDisplayMgr->activeDialog->FindSubView(kControlTagMain);
  mainPanel->AssertValid();
  mainPanel->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005dbe10
void TViewMgr::ShowHighScoreScreen() {
  TView* mainPanel = g_pDisplayMgr->activeDialog->FindSubView(kControlTagMain);
  mainPanel->AssertValid();
  mainPanel->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005dc160
void TViewMgr::RefreshActiveGoldControlAndUiRuntimeState() {
  g_pMacViewMgr->RefreshActiveGoldControlAndUiRuntimeState();
}

// FUNCTION: IMPERIALISM 0x005dc180
void TViewMgr::CreateMapArtStorage() {
  g_pMacViewMgr->CreateMapArtStorage();
}

// FUNCTION: IMPERIALISM 0x005dc1a0
void TViewMgr::GenerateRegions() {
  g_pMacViewMgr->GenerateRegions();
}

// FUNCTION: IMPERIALISM 0x005dc1c0
void TViewMgr::GenerateMiniMap() {
  g_pMacViewMgr->GenerateMiniMap();
}

// FUNCTION: IMPERIALISM 0x005dc1e0
void TViewMgr::InitializeCitySiteSelectionScreenForNation(int nationSlot) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;

  TToolBarCluster* toolbar =
      static_cast<TToolBarCluster*>(activeDialog->FindSubView(kControlTagTool));
  toolbar->AssertValid();
  toolbar->SetReadouts(static_cast<short>(nationSlot));

  TCitySiteView* citySiteView =
      static_cast<TCitySiteView*>(activeDialog->FindSubView(kControlTagDialog));
  citySiteView->AssertValid();
  g_pGlobalMapState->DimByValidCitySite(static_cast<short>(nationSlot));
  TGreatPower* nation = g_apNationStates[static_cast<short>(nationSlot)];
  TCity* city = nation != NULL ? nation->city : NULL;
  citySiteView->pendingTown = city->homeTownMarker;
  citySiteView->SetMapViewTileIndex(
      g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(nationSlot));

  TMapUberPicture* mainPicture =
      static_cast<TMapUberPicture*>(activeDialog->FindSubView(kControlTagMain));
  mainPicture->AssertValid();
  mainPicture->DisplayMiniMap();

  CString messageBody;
  CString titleSuffix;
  g_pSimMgr->GetString(0x273f, 4, &messageBody);
  g_pSimMgr->GetString(0x273f, 3, &titleSuffix);
  ModalMessage(4, titleSuffix, messageBody, g_ptCitySiteSelectionDialogPlacement, 2, 0);
}

// FUNCTION: IMPERIALISM 0x005dc3f0
void TViewMgr::ConfigureMapEditorGoldValueGrid() {
  TWorldView* mapDialog = static_cast<TWorldView*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->FindSubView(kControlTagDialog))); // 'DLOG'
  mapDialog->AssertValid();
  mapDialog->SetMapViewCellCoordinates(0x14, 0x14);
}

// FUNCTION: IMPERIALISM 0x005dc430
void TViewMgr::ShowBuildingExpansionDialog(short buildingSlotId, TCity* city,
                                           TCityProductionView* productionView) {
  TWindow* node =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGenericExpander);
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xf50);
  }
  node->SetModality(true);
  TBuildingExpansionView* expansionView =
      static_cast<TBuildingExpansionView*>(node->FindSubView(kControlTagDialog)); // 'DLOG'
  expansionView->AssertValid();
  if (expansionView == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgr, 0xf54);
  }
  expansionView->StuffValues(buildingSlotId, city, productionView);
  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  int dialogAction = node->PoseModally();
  expansionView->DoClosingAction(static_cast<unsigned long>(dialogAction));
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dc690
void TViewMgr::ShowUnitHistory(short nationSlot) {
  struct TurnHistoryRecord {
    short turnNumber;
    short messageKind;
    short subjectStringIndex;
    short subjectCount;
  };

  CString lineText;
  CString messageText;
  CString countText;

  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TToolBarCluster* toolbar =
      static_cast<TToolBarCluster*>(activeDialog->FindSubView(kControlTagTool));
  toolbar->AssertValid();
  if (toolbar != 0) {
    toolbar->SetReadouts(nationSlot);
  }

  TPtrList* history = g_apNationStates[nationSlot]->turnSummaryQueue;
  int historyCount = history->GetSize();
  if (historyCount <= 0) {
    return;
  }

  int entryOrdinal;
  if (historyCount > 20) {
    entryOrdinal = historyCount - 20;
  } else {
    entryOrdinal = 1;
  }
  while (entryOrdinal <= history->GetSize()) {
    TurnHistoryRecord* record =
        static_cast<TurnHistoryRecord*>(history->GetPtrListEntryByOneBasedIndex(entryOrdinal));

    countText.Format(g_szDecimalFormat, record->subjectCount);
    switch (record->messageKind) {
    case 0:
    case 1:
      if (record->subjectCount > 1) {
        g_pSimMgr->GetString(0x271a, record->subjectStringIndex, &messageText);
      } else {
        g_pSimMgr->GetString(0x2716, record->subjectStringIndex, &messageText);
      }
      break;
    case 2:
      if (record->subjectCount > 1) {
        g_pSimMgr->GetString(0x2748, record->subjectStringIndex, &messageText);
      } else {
        g_pSimMgr->GetString(0x2718, record->subjectStringIndex, &messageText);
      }
      break;
    case 3:
      if (record->subjectCount > 1) {
        BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &messageText, 0x2747, 1, 0x2717,
                                              record->subjectStringIndex);
      } else {
        BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &messageText, 0x2747, 0, 0x2717,
                                              record->subjectStringIndex);
      }
      break;
    }

    lineText.Format(g_szDecimalFormat, record->turnNumber);
    lineText = s_szTurnHistoryPrefix + lineText + s_szTurnHistorySeparator;
    lineText += countText + s_szSpaceSeparator + messageText;

    TStaticText* textControl =
        static_cast<TStaticText*>(activeDialog->FindSubView(kControlTagTxtAt + entryOrdinal));
    if (textControl != 0) {
      textControl->Show(1, 1);
      textControl->SetTextAndMaybeRefresh(&lineText, true);
    }

    ++entryOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x005dcaa0
void TViewMgr::MakeGameSetupDialog() {
  TGameSetupOptionsDialog dialog(NULL);

  GameSetup* setup = new GameSetup;
  if (setup != 0) {
    InitializeGameSetupFromDefaultNationPolicies(setup);
    dialog.SetGameSetupValues(setup);

    int modalResult = dialog.DoModal();
    if (modalResult != 0) {
      g_pSimMgr->SetGameSetupValues(setup);
    }
    delete setup;
  }
}

// ORACLE: Mac MakeCheaterDialog. Reads nothing from `this`.
// FUNCTION: IMPERIALISM 0x005de6c0
void TViewMgr::MakeCheaterDialog(int which) {
  TWindow* panel =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(static_cast<TurnEventId>(15000));
  if (panel == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UViewMgr.more.cpp", 0x303);
  }

  TCheater* cheater = 0;
  if (which == 0) {
    TTechCheater* techCheater = new TTechCheater();
    techCheater->ITechCheater(panel);
    cheater = techCheater;
  } else if (which == 1) {
    TGPCheater* gpCheater = new TGPCheater();
    gpCheater->IGPCheater(panel);
    cheater = gpCheater;
  }

  panel->PoseModally();
  cheater->ApplyCheats();
  panel->Close();
  panel->Free();
}
