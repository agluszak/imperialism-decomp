#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_widgets/TArmyInfoView.h"
#include "game/city_ui/TBuildingExpansionView.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_widgets/TCivReport.h"
#include "game/ui_widgets/TTown.h"
#include "game/ui_screens/TOffLimitsPicture.h"
#include "game/city_ui/TPlaceCityDialog.h"
#include "game/ui_widgets/TCombatReportView.h"

#include "game/trade_ui/TDealBookPicture.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"

#include "game/turn_event_dialog_provisional.h"
#include "game/resource_domain_types.h"

#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TSoundPlayer.h" // g_pSfxPlaybackSystem
#include "game/ui_core/TMacViewMgr.h"     // g_pStrategicMapViewSystem
#include "game/ui_core/TIncludeView.h"    // turn-event UI entry packet ('Incl')
#include "game/ui_core/CWMgrIterator.h"   // window-registry traversal for the full (code-0) refresh
#include "game/ui_core/quickdraw_rendering.h" // SetQuickDrawFillColor / SetQuickDrawStrokeColor
#include "game/ui_widgets/TToolBarCluster.h" // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/ui_widgets/TTradeCluster.h"
#include "game/assets/TMovieView.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/city_ui/TCountry.h" // FormatOverlayTerrainLabelText (terrain overlay case)
#include "game/nation/TGreatPower.h"
#include "game/military_ui/TSortedByRelationshipList.h"
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
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_text_label_helpers_decls.h"

#include <new>

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pSimMgr / turn-state
// manager). Included via global_data_tables.h.

// The display/GWorld manager (g_pDisplayMgr @ 0x6a2158); its activeDialog (+0x04) field
// holds the active main TView used as the dispatch root for turn-event UI refreshes.

#include "game/ui_core/CIncludeView.h"

// The former RunNationInfoModalAndReturnNonCancel / NoOpUiRuntimeCallback_005db2f0 /
// NoOpRuntimeCallback_005d5d10 extern bridges are gone: the modal is a real TViewMgr
// method now, and the two "NoOp" callbacks were mis-named out-of-line COMDAT copies of
// CString::GetLength / CString::GetPchData that the tail call sites use via the real
// CString API.

// Provisional dispatch interfaces for the runtime-resolved turn-event dialog node and
// its 'GOLD' child control now live in one shared header so the TViewMgr and
// TMacViewMgr copies can't drift apart (bd imperialism-decomp-hpd.7). The lower slots
// (ResolveControlByTag, Locate, Close, Free, AssertValid) are real
// inherited TView/TObject virtuals dispatched directly.
namespace {
using turn_event_dialog::GoldCommitControl;
using turn_event_dialog::GoldDialogControl;
// g_pUiViewManager (TAssetMgr) @ 0x6a2148 — the UI/view asset registry that resolves
// turn-event dialog nodes by message context.
const unsigned int kAddrDefaultGameSetupPolicies = 0x00698b1a;
const unsigned int kAddrDefaultGameSetupPoliciesEnd = 0x00698b52;
} // namespace

namespace {
const unsigned int kAddrClassDescTViewMgr = 0x0066f0b8;
} // namespace

HCURSOR LoadTurnEventCursorByResourceIdOffset1000(int cursorResourceId);

// The RTTI/CRuntimeClass oracle previously assigned TViewMgr::CreateObject to
// 0x005d4c60, but that address's real body (verified via `just ghidra listing`
// and `just ghidra decompile`) is a CString truncate-with-ellipsis text helper --
// no `operator new` call, no vtable store, just MeasureTextExtentWithCachedQuick-
// DrawStyle + CString::Mid + string concatenation. It is now ported for real as
// TruncateTextToFitWidthWithEllipsis (quickdraw_rendering.cpp, 0x5d4c60). TViewMgr's
// real CreateObject address is unknown; leaving this class's DYNCREATE CreateObject
// unclaimed rather than reinstating the wrong pairing.
IMPLEMENT_DYNCREATE(TViewMgr, TObject)

// SYNTHETIC: IMPERIALISM 0x005d5040
// TViewMgr::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x005d5060
TViewMgr::TViewMgr() : TObject() {
  this->fieldEc = 0;
  this->currentTurnEventCode = 0;
  this->dialogPlacement08 = g_ptCitySiteSelectionDialogPlacement;
  this->field10 = 0;
  this->mapUberPictureF0 = 0;
  this->activeMovieViewF4 = 0;
  this->fieldF8 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005d50b0
// TViewMgr::`scalar deleting destructor'
TViewMgr::~TViewMgr() {}

// SYNTHETIC: IMPERIALISM 0x005d50e0
// TViewMgr::~TViewMgr

// FUNCTION: IMPERIALISM 0x005d5100
void TViewMgr::LoadTurnEventCursorTable() {
  for (int i = 0; i < 0x36; i++) {
    turnEventCursors[i] = LoadTurnEventCursorByResourceIdOffset1000(i + 1000);
  }
}

// FUNCTION: IMPERIALISM 0x005d5140
HCURSOR LoadTurnEventCursorByResourceIdOffset1000(int cursorResourceId) {
  CString cursorName;
  cursorName.Format(s_TurnEventCursorNameFormat_0069B6B4, cursorResourceId);
  AFX_MODULE_STATE* moduleState = AfxGetModuleState();
  return LoadCursorA(moduleState->m_hCurrentInstanceHandle, cursorName);
}

// FUNCTION: IMPERIALISM 0x005d51e0
void TViewMgr::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x005d5200
void TViewMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  this->fieldEc = 0;
  this->currentTurnEventCode = 0;
  this->dialogPlacement08 = g_ptCitySiteSelectionDialogPlacement;
  this->field10 = 0;
  this->mapUberPictureF0 = 0;
}

// FUNCTION: IMPERIALISM 0x005d5250
void TViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x005d5270
QuickDrawPaletteIndex TViewMgr::GetColor(short eventCode) {
  if (200 < eventCode) {
    if (eventCode < 0x2b68) {
      if (eventCode == 0x2b67) {
        return 0;
      }
      switch (eventCode) {
      case 0xc9:
        goto case_33;
      case 0xca:
        return 0x30;
      case 0xcb:
        goto case_6;
      case 0xcc:
        goto case_3b;
      case 0xcd:
        return 0x24;
      case 0xce:
        return 0x26;
      case 0xcf:
        goto case_34;
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
    case_6:
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
    case_33:
      return 0x2d;
    case 0x34:
    case_34:
      return 0x18;
    case 0x37:
      return 0xbd;
    case 0x3a:
      return 0xc6;
    case 0x3b:
    case_3b:
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
void TViewMgr::SetColor(short colorCode, unsigned char foreground) {
  QuickDrawPaletteIndex paletteIndex = GetColor(colorCode);
  if (foreground != 0) {
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
void TViewMgr::HandleTurnEventVtableSlot40RefreshGoldDialog() {
  if (IsTurnFlowCooldownActiveAndResetExpiredState() != 0) {
    return;
  }
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventConfirmEndTurn));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x223);
  }
  node->SetModality(1);
  if (node->ResolveControlByTag(kControlTagDialog) == nullptr) { // 'GOLD'
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x227);
  }
  TDialogBehavior* content = node->GetDialogBehavior();
  if (content != nullptr) {
    content->defaultCommandCode = kControlTagPic5; // 'cip5'
  }

  CPoint placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->Locate(placement, 0);

  TPicture* gold = static_cast<TPicture*>(node->ResolveControlByTag(kControlTagDialog)); // 'DLOG'
  gold->AssertValid();
  gold->SetPictureResourceIdAndRefresh(static_cast<short>(0x24cd), 0);

  // Mask the game-flow flag while committing the refresh when localization mode is active.
  unsigned char savedFlag = 0;
  bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
  if (multiplayerActive) {
    savedFlag = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
  }
  node->PoseModally();
  node->Close();
  node->Free();
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    g_pGameFlowState->processPrimaryEventQueue = savedFlag;
  }
}

// FUNCTION: IMPERIALISM 0x005d5960
int TViewMgr::ClassifyTurnStateForOverlayMode() {
  switch (*reinterpret_cast<short*>(&g_pSimMgr->mode)) {
  case 6:
  case 0xc:
  case 0xe:
  case 0xf:
  case 100:
  case 0x66:
  case 0x67:
  case 0x68:
    return 0;
  case 10:
  case 0xd:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x19:
  case 0x65:
    return 1;
  default:
    return 2;
  }
}

// FUNCTION: IMPERIALISM 0x005d5a70
void TViewMgr::ModalMessage(CString message, const POINT& messagePosition) {
  int overlayMode = this->ClassifyTurnStateForOverlayMode();
  this->ModalMessage(message, messagePosition, overlayMode, 0);
}

// FUNCTION: IMPERIALISM 0x005d5b00
char TViewMgr::ModalMessage(CString message, const POINT& messagePosition, short overlayMode,
                            unsigned char showCancel) {
  return this->ModalMessage(3, CString(g_szEmptyString), message, messagePosition, overlayMode,
                            showCancel);
}

// FUNCTION: IMPERIALISM 0x005d5c40
char TViewMgr::ModalMessage(long templateKind, CString formatText, CString message,
                            const POINT& messagePosition, short overlayMode,
                            unsigned char showCancel) {
  return RunNationInfoModalAndReturnNonCancel(templateKind, formatText,
                                              static_cast<LPCSTR>(message), message.GetLength(),
                                              messagePosition, overlayMode, showCancel);
}

// FUNCTION: IMPERIALISM 0x005d5d30
bool TViewMgr::RunNationInfoModalAndReturnNonCancel(int messageKind, CString titleSuffix,
                                                    const char* messageChars, int messageLength,
                                                    const POINT& messagePosition, int contextTag,
                                                    char showCancel) {
  CString titleText;
  TextStyle styleDescriptor;
  CRect bounds;            // function-scope like the original (0x38): not overlapped with the
  short overlaySfxIds[13]; // sfx table (0x48), so the frame keeps both live regions
  // The payload is a {-1000 sentinel, resource word} pair; the word is only read
  // through a short lvalue over the pre-zeroed int (word stores/compares, dword pass).
  int payloadResource;
  // The original zeroes the four styleRef6 bytes individually (0x5d5d69..0x5d5d85).
  char* styleRefBytes = reinterpret_cast<char*>(&styleDescriptor.textColor);
  styleRefBytes[0] = 0;
  styleRefBytes[1] = 0;
  styleRefBytes[2] = 0;
  styleRefBytes[3] = 0;
  payloadResource = 0;
  if (messagePosition.x == -1000) {
    *reinterpret_cast<short*>(&payloadResource) = static_cast<short>(messagePosition.y);
  }
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);

  TWindow* dialog;
  if (static_cast<short>(payloadResource) == 0) {
    dialog = static_cast<TWindow*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMinisterMessage));
  } else {
    g_pUiViewManager->OpenFilesFor(0xb);
    dialog = static_cast<TWindow*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMinisterReward));
  }
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x2e9);
  }
  dialog->SetModality(1);
  TDialogBehavior* content = dialog->GetDialogBehavior();
  if (content != 0) {
    content->defaultCommandCode = kControlTagOkay; // 'okay'
  }

  CPoint placement;
  this->ComputeTurnEventDialogPlacementByCode(dialog, &placement);
  dialog->Locate(placement, 0);

  TPicture* gold = static_cast<TPicture*>(dialog->ResolveControlByTag(kControlTagDialog)); // 'DLOG'
  gold->AssertValid();
  if (gold == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x2fa);
  }
  int contextTagSx = static_cast<short>(contextTag);
  int goldResource = contextTagSx * 2 + 0x24cd;
  if (static_cast<short>(contextTag) == 2 && g_nationInfoGoldResourceOverride_006a5bac != 0) {
    goldResource = g_nationInfoGoldResourceOverride_006a5bac;
  }
  gold->SetPictureResourceIdAndRefresh(static_cast<short>(goldResource), 0);

  TPicture* coat = static_cast<TPicture*>(dialog->ResolveControlByTag(kControlTagCoat)); // 'coat'
  coat->AssertValid();
  if (coat == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x301);
  }
  if (g_pSimMgr->GetActiveNationId() >= 0 && g_pSimMgr->GetActiveNationId() < 7) {
    coat->SetPictureResourceIdAndRefresh(
        static_cast<short>(g_pSimMgr->GetActiveNationId() + 0x251c), 0);
  } else {
    coat->SetEnabled(0, 0);
  }

  if (static_cast<short>(payloadResource) != 0) {
    TPicture* goldValue =
        static_cast<TPicture*>(dialog->ResolveControlByTag(kControlTagDialog)); // 'DLOG'
    goldValue->AssertValid();
    goldValue->SetPictureResourceIdAndRefresh(static_cast<short>(contextTag + 0x252a), 0);
    TPicture* award =
        static_cast<TPicture*>(dialog->ResolveControlByTag(kControlTagRewa)); // 'awer'
    award->AssertValid();
    award->SetPictureResourceIdAndRefresh(static_cast<short>(payloadResource), 0);
  } else {
    TStaticText* title =
        static_cast<TStaticText*>(dialog->ResolveControlByTag(kControlTagTitl)); // 'titl'
    title->AssertValid();
    if (title == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x31a);
    }
    title->InstallTextStyle(styleDescriptor, 0);
    title->SetTextAlignmentAndMaybeRefresh(1, 0);
    BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &titleText, 0x2749, messageKind, 0x2749,
                                          contextTagSx);
    titleText += '\r';
    titleText += '\r';
    titleText += titleSuffix;
    title->SetTextAndMaybeRefresh(&titleText, 0);
  }

  TDeluxeText* info =
      static_cast<TDeluxeText*>(dialog->ResolveControlByTag(kControlTagInfo)); // 'info'
  info->AssertValid();
  info->SetTextEntryFromChars(messageChars, messageLength);
  info->SetTextStyle(styleDescriptor, 0);
  int measuredHeight = static_cast<short>(info->MeasureCurrentTextHeightInLayoutRect());
  if (measuredHeight > info->frameHeight38) {
    info->QueryBounds(&bounds);
    bounds.right = bounds.top - 10;
    info->ApplyBounds(&bounds, 0);
    if (measuredHeight > info->frameHeight38) {
      TScrollView* scrollView = new TScrollView();
      scrollView->IScrollView(gold, &info->ownerLocalX, &info->frameWidth34);
      scrollView->DoPostCreate(0);
      gold->DetachChildFromOwnerList(info);
      scrollView->AttachChildControl(info, 0);
      bounds.top = 0;
      bounds.left = 0;
      bounds.bottom = measuredHeight;
      bounds.right = info->frameWidth34 - 0x1c;
      info->ApplyBounds(&bounds, 0);
      scrollView->contentView60 = info;
      scrollView->SyncBoundedValueAndToggleControlStates();
    }
  }

  if (showCancel != 0) {
    TView* cancel = dialog->ResolveControlByTag(kControlTagCncl); // 'cncl'
    cancel->AssertValid();
    cancel->SetEnabled(1, 1);
    cancel->SetState(1, 0);
  }

  unsigned char savedProcessFlag;
  bool simSuppressed = g_pSimMgr->multiplayerSessionRole != 0;
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
    overlaySfxIds[5] = static_cast<short>(g_overlaySfxSeasonWord_0066f0a6 + 0xbb8);
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
  simSuppressed = g_pSimMgr->multiplayerSessionRole != 0;
  if (simSuppressed) {
    g_pGameFlowState->processPrimaryEventQueue = savedProcessFlag;
  }
  if (modalResult == kControlTagCncl) { // 'cncl'
    return false;
  }
  return true;
}

static void InitializeGameSetupFromDefaultNationPolicies(GameSetup* setup) {
  const short* src = reinterpret_cast<const short*>(kAddrDefaultGameSetupPolicies);
  const short* srcEnd = reinterpret_cast<const short*>(kAddrDefaultGameSetupPoliciesEnd);
  short* dst = setup->cityMinisterPolicyIds;
  while (src < srcEnd) {
    dst[-7] = src[-1];
    dst[0] = src[0];
    dst[7] = src[1];
    dst[0xe] = src[2];
    ++dst;
    src += 4;
  }
}

// Per-mode overlay message/dialog builder: each case composes messageText (and picks
// the modal's resource word + dialog context) before the tail hands everything to
// RunNationInfoModalAndReturnNonCancel with the {-1000, resourceId} payload pair.
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
    short nationId = g_pSimMgr->GetActiveNationId();
    int cap = g_pCityOrderCapabilityState->nationCapRows1e8[nationId].slots[9];
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
    g_apTerrainTypeDescriptorTable[contextArg]->LoadNationDisplayNameSharedRefFromField8(
        &nationNameText);
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
  RunNationInfoModalAndReturnNonCancel(overlayMode, CString(g_pNationInfoEmptyText_0066f050),
                                       static_cast<LPCSTR>(messageText), messageText.GetLength(),
                                       modalPosition, dialogContext, 0);
}

// FUNCTION: IMPERIALISM 0x005d69b0
void TViewMgr::ComputeTurnEventDialogPlacementByCode(TView* dialogView, POINT* outPlacement) {
  CRect mainBounds;
  g_pDisplayMgr->activeDialog->QueryBounds(&mainBounds);
  (void)mainBounds; // original makes the call but discards the result

  CIncludeView* mainView = GetMainViewHostFromActiveThread();
  RECT clientRect;
  GetClientRect(mainView->m_hWnd, &clientRect);

  CRect dialogBounds;
  dialogView->QueryBounds(&dialogBounds);
  int dlgWidth = dialogBounds.right - dialogBounds.left;
  int dlgHeight = dialogBounds.bottom - dialogBounds.top;

  // Center the dialog inside a per-event "design" rectangle, offset by the host
  // client origin. Most turn-event codes use the default bucket; a handful pick
  // the wider/taller special buckets.
  int designWidth = 0x276;
  int designHeight = 0x1d1;
  int margin = 0x1e;
  short code = this->currentTurnEventCode;
  if (code == kTurnEventCitySiteSelector || code == kTurnEventStrategicMap) {
    designWidth = 0x200;
    designHeight = 0x1c0;
    margin = 0x16;
  } else if ((code >= kTurnEventDiplomacyMap && code <= kTurnEventCityProduction) ||
             code == kTurnEventTransport || code == kTurnEventTechnologyAdvance ||
             code == kTurnEventProvisional0F3C || code == kTurnEventTacticalView ||
             code == kTurnEventOfferSheet || code == kTurnEventDealBook) {
    designHeight = 0x1c0;
  }

  outPlacement->x = (designWidth - dlgWidth) / 2 + clientRect.left + 5;
  outPlacement->y = (designHeight - dlgHeight) / 2 + clientRect.top + margin;
}

// FUNCTION: IMPERIALISM 0x005d6b70
void TViewMgr::RefreshMainViewNationIndicatorForCurrentTurnEvent() {
  TView* mainView = g_pDisplayMgr->activeDialog;
  if (mainView == nullptr) {
    return;
  }
  // Turn-event 0x7DD targets the 'trb1' toolbar tag; everything else the 'tool' tag.
  TControl* control;
  if (this->currentTurnEventCode == kTurnEventStrategicMap) {
    control = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagTbr1));
  } else {
    control = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagTool));
  }
  if (control != nullptr) {
    static_cast<TToolBarCluster*>(control)->UpdateControlTagTreaTextFromNationAndMapContext(
        g_pSimMgr->GetActiveNationId());
  }
}

// FUNCTION: IMPERIALISM 0x005d6bf0
void TViewMgr::AddPendingTurnOverlayCode(int modeValue) {
  fieldEc = static_cast<short>(fieldEc + static_cast<short>(modeValue));
}

// FUNCTION: IMPERIALISM 0x005d6c10
short TViewMgr::GetPendingTurnOverlayCode() {
  return fieldEc;
}

// FUNCTION: IMPERIALISM 0x005d6c30
void TViewMgr::RefreshStrategicMapStatusIconsForActiveNation() {
  static const char kStatusIconTagBytes[] =
      " 0sr 1sr 2sr 3sr 4sr 5sr 6sr 0am 1am 2am 3am 4am 5am 0dg 1dg 2dg 3dg";
  TView* mainView = g_pDisplayMgr->activeDialog;
  const short nationId = this->currentTurnEventNationSlot06;
  for (short iconIndex = 0; iconIndex < 0x12; ++iconIndex) {
    const unsigned int tag =
        *reinterpret_cast<const unsigned int*>(kStatusIconTagBytes + iconIndex * 4);
    TView* control = mainView->ResolveControlByTag(tag);
    if (control != nullptr) {
      control->AssertValid();
      g_pStrategicMapViewSystem->ApplySellOrderRowToNationState(
          static_cast<TTradeCluster*>(control), iconIndex, nationId);
    }
  }
  TGreatPower* nation = g_apNationStates[nationId];
  if (nation != nullptr) {
    nation->SnapshotDiplomacyState1c6Into250();
  }
}

// FUNCTION: IMPERIALISM 0x005d6cd0
void TViewMgr::HandleTurnEventDialogFactorySlot70(int eventCode) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(eventCode), 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x4ff);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->Open();
}

// FUNCTION: IMPERIALISM 0x005d6d70
void TViewMgr::HandleTurnEventDialogFactorySlot74(int eventCode) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(eventCode), 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x514);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6e30
void TViewMgr::NoOpTurnEventStateVtableSlot8C(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x005d6e50
void TViewMgr::HandleTurnEventDialogFactorySlot78(int eventCode) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(eventCode), 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x535);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6f10
void TViewMgr::HandleTurnEventDialogFactorySlot7C(int eventCode) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(eventCode), 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x54e);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6fd0
void TViewMgr::HandleTurnEventDialogFactorySlot80(int eventCode) {
  TWindow* node =
      static_cast<TWindow*>(g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
          static_cast<TurnEventId>(eventCode), 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x566);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d7090
char TViewMgr::MakeDiplomacyOfferDialog(short sourceNation, short targetNation,
                                        short proposalCode) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), sourceNation);
  TDiplomacyMapView* mainView =
      static_cast<TDiplomacyMapView*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainView->AssertValid();
  mainView->PoseOffer(static_cast<short>(sourceNation), static_cast<short>(targetNation),
                      static_cast<short>(proposalCode));
  return 0;
}

// FUNCTION: IMPERIALISM 0x005d7100
char TViewMgr::PoseWarOfferIfTurnFlowReady(int sourceNation, int arg1, int arg2, int promptCode) {
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return 1;
  }
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), sourceNation);
  TDiplomacyMapView* mainView =
      static_cast<TDiplomacyMapView*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainView->AssertValid();
  return mainView->PoseWarOffer(static_cast<short>(sourceNation), arg1, arg2, promptCode);
}

// FUNCTION: IMPERIALISM 0x005d7190
void TViewMgr::NoOpTurnEventStateVtableSlotD4(int arg) {
  (void)arg;
}

// Clears style bit 0x02000000 on the main view's host window.
static void ModifyMainViewChildWindowStyleClear02000000(TView* mainView) {
  if (mainView->nativeWindow50 != nullptr) {
    mainView->nativeWindow50->ModifyStyle(0, 0x02000000);
  }
}

namespace turn_event_ui_refresh {

TView* ActiveMainView() {
  return g_pDisplayMgr->activeDialog;
}

TControl* ResolveMainTaggedControl(unsigned int controlTag) {
  TView* mainView = ActiveMainView();
  if (mainView == nullptr) {
    return nullptr;
  }
  return static_cast<TControl*>(mainView->ResolveControlByTag(controlTag));
}

void BindCursorPanelAndSetTurnEventCodeRange() {
  TControl* cursor = ResolveMainTaggedControl(kControlTagCurs);
  g_pCursorControlPanel = static_cast<TInfoBarText*>(cursor);
  if (cursor != nullptr) {
    cursor->AssertValid();
    static_cast<TInfoBarText*>(cursor)->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
  }
}

// The original (0x5d83b0) dispatches vtable slot 0x39 (RefreshControl) on the
// 'main' panel — a generic refresh that is safe for any screen's main panel.
// It must NOT be the direct TCouncilView ticker init (0x4fc2e0): on non-council
// screens (e.g. the combined map, whose 'main' has no can0/can1 children) that
// misdispatch dereferences a null control and crashes.
void RefreshMainPanelControl() {
  TControl* mainPanel = ResolveMainTaggedControl(kControlTagMain);
  if (mainPanel != nullptr) {
    mainPanel->AssertValid();
    mainPanel->RefreshControl();
  }
}

void RefreshToolBarClusterByTag(unsigned int controlTag) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(control);
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetActiveNationId());
  toolbar->RefreshTurnOrderStatusPanelTextsAndControls();
}

void RefreshOrderStatusPicture(unsigned int controlTag, unsigned int flagMask,
                               short pictureWhenFlagSet, short pictureWhenFlagClear) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  const short pictureId =
      g_pSimMgr->TestTurnFlowStatusFlagMask(flagMask) ? pictureWhenFlagSet : pictureWhenFlagClear;
  static_cast<TPicture*>(control)->SetPictureResourceIdAndRefresh(pictureId, true);
}

void RefreshTradClusterPictureAndHintText() {
  TControl* tradControl = ResolveMainTaggedControl(kControlTagTrad);
  if (tradControl == nullptr) {
    return;
  }
  tradControl->AssertValid();
  TPicture* tradPicture = static_cast<TPicture*>(tradControl);
  const short pictureId = static_cast<short>(tradPicture->glyphBase84 + 1);
  tradPicture->SetPictureResourceIdAndRefresh(pictureId, false);
  tradControl->SetState(0, 0);

  CString hintText;
  g_pSimMgr->GetString(0x2730, 0, &hintText);
  tradControl->SetHoverHelpText(hintText);
}

void RefreshTaggedControlWithLocalizedString(unsigned int controlTag, short stringCode,
                                             short stringIndex) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  CString localizedText;
  g_pSimMgr->GetString(stringCode, stringIndex, &localizedText);
  control->SetHoverHelpText(localizedText);
}

void ApplyThemeToTaggedTextControl(unsigned int controlTag, int styleWidth, int stylePrimary,
                                   int styleSecondary) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  TextStyle styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, styleWidth, styleSecondary);
  control->InstallTextStyle(styleDescriptor, 0);
  (void)stylePrimary;
}

void RefreshQuerControlLayoutAndClearText() {
  TControl* querControl = ResolveMainTaggedControl(kControlTagQuer);
  if (querControl == nullptr) {
    return;
  }
  querControl->AssertValid();
  CPoint layoutPosition(0, 0);
  querControl->Locate(layoutPosition, 0);
  querControl->SetHoverHelpText(g_szEmptyString);
}

} // namespace turn_event_ui_refresh

namespace {
void DispatchPostTurnStateUpdatesTail() {
  if (g_pHelpMgr == nullptr) {
    return;
  }
  if (IsTurnFlowCooldownActiveAndResetExpiredState() != 0) {
    return;
  }
  g_pHelpMgr->HandlePostDispatchTurnStateEventUpdates();
  g_pHelpMgr->HandlePendingEventActivationByCode(g_pUiRuntimeContext->currentTurnEventCode);
  g_pHelpMgr->HandlePostPendingEventActivationNoOp(g_pUiRuntimeContext->currentTurnEventCode);
}
} // namespace

// FUNCTION: IMPERIALISM 0x005d71b0
void TViewMgr::DispatchNationActionToMainControl(int sourceNation, int arg1, int arg2, int arg3,
                                                 int targetNation) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  turn_event_dialog::MainActionControl* mainControl =
      static_cast<turn_event_dialog::MainActionControl*>(
          activeDialog->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();
  if (mainControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x5c7);
  }
  mainControl->InvokeMainAction(sourceNation, arg1, arg2, arg3, targetNation);
}

// FUNCTION: IMPERIALISM 0x005d7240
void TViewMgr::DispatchTurnEvent(TurnEventCodeStorage eventCode, int payload) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  const TurnEventCodeStorage newCode = eventCode;
  const short secondary = static_cast<short>(payload);

  // Sound cue when the turn-flow mode is in the 0x67..0x6a band and the code changed.
  if (newCode != this->currentTurnEventCode) {
    switch (static_cast<short>(g_pSimMgr->mode)) {
    case 0x67:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5b);
      break;
    case 0x68:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5c);
      break;
    case 0x69:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5e);
      break;
    case 0x6a:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5d);
      break;
    }
  }

  // Teardown hook for the code currently displayed.
  const int curCode = this->currentTurnEventCode;
  if (curCode < 0x2135) {
    if (curCode == kTurnEventOfferSheet) {
      ModifyMainViewChildWindowStyleClear02000000(mainView);
    } else {
      switch (curCode) {
      case kTurnEventTradeOverview:
      case kTurnEventIndustryOverview:
        this->RefreshStrategicMapStatusIconsForActiveNation();
        break;
      case kTurnEventCityProduction:
        g_pStrategicMapViewSystem->ClearActiveCityProductionViewAndDiscardRegion();
        break;
      case kTurnEventStrategicMap:
        this->mapUberPictureF0 = 0;
        break;
      }
    }
  }

  // Code 0 = rebuild every registered UI window node.
  if (newCode == 0) {
    g_pGlobalUiRootController->dispatchBusyFlag4c = 0;
    this->currentTurnEventCode = 0;
    g_pDisplayMgr->clipSnapshotEvent = 0;
    mainView->Close();
    CWMgrIterator iter;
    iter.Reset(1);
    TWindow* window = static_cast<TWindow*>(iter.FirstWindow());
    while (iter.More() != 0) {
      const unsigned int tag = static_cast<unsigned int>(window->controlTag);
      if (tag == kControlTagMapW || tag == kControlTagTrnW) {
        window->CloseAndFree();
      }
      window = static_cast<TWindow*>(iter.NextWindow());
    }
    return;
  }

  // Same-code refresh: refresh the main view, then run the per-code hook.
  if (newCode == this->currentTurnEventCode) {
    if (secondary != -1) {
      this->currentTurnEventNationSlot06 = secondary;
    }
    if (newCode == kTurnEventNetworkGameOptions) {
      QueueDeferredUiEventPacket(mainView, 0x29a, mainView);
    } else if (newCode == kTurnEventDiplomacyOffer) {
      mainView->RefreshControl();
      g_pCursorControlPanel->AssertValid();
    } else if (newCode == kTurnEventTechnologyStore) {
      mainView->RefreshControl();
      this->RefreshTechnologyStorePageAndHudText(0);
    } else if (newCode == kTurnEventDiplomacyMap) {
      if (static_cast<short>(g_pSimMgr->mode) == 0x68) {
        mainView->RefreshControl();
        this->HandleTurnEvent7D8_ActivateDiplomacyMapView(newCode);
      }
    } else if (newCode == kTurnEventTradeOverview || newCode == kTurnEventIndustryOverview) {
      mainView->RefreshControl();
      this->HandleTurnEvent7D9Or7DA_UpdateNationResourceAdvisor(secondary);
    } else if (newCode == kTurnEventCityProduction) {
      mainView->RefreshControl();
      this->HandleTurnEvent7DB_SelectCityAndRefreshView(secondary);
    } else if (newCode == kTurnEventStrategicMap) {
      mainView->RefreshControl();
      this->HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(newCode);
    } else if (newCode == kTurnEventTransport) {
      mainView->RefreshControl();
      this->HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary(newCode);
    } else if (newCode == kTurnEventNewspaperStatus) {
      this->HandleTurnEvent2103_RunNationStatusReportUpdate();
    } else if (newCode == kTurnEventDealBook) {
      mainView->RefreshControl();
      this->HandleTurnEvent2260_RefreshMainHudTitles(newCode);
    }
    DispatchPostTurnStateUpdatesTail();
    return;
  }

  // Cross-code path: tear down the previous dialog, build the new turn-event UI packet.
  g_pUiViewManager->OpenFilesForView(0);
  mainView->Open();
  if (this->field10 != 0) {
    ShowBlockingWaitOverlayDialog();
    this->field10 = 0;
  }
  TControl* inclControl =
      static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagIncl)); // 'Incl'
  if (inclControl != nullptr) {
    inclControl->AssertValid();
    inclControl->RefreshControl();
    inclControl->Free();
  }
  if (newCode != kTurnEventTechnologyAdvance) {
    this->currentTurnEventNationSlot06 = secondary;
  }

  TIncludeView* packet = ::new TIncludeView();
  CString emptyText(g_szEmptyString);
  CPoint anchorPoint(0, 0);
  packet->BuildTurnEventFactoryPacket(nullptr, mainView, newCode, anchorPoint, &emptyText, 1);
  packet->DoPostCreate(0);
  packet->controlTag = kControlTagIncl; // 'Incl'
  packet->RefreshControl();
  g_pDisplayMgr->UpdateTheGWorld(newCode);
  if (this->field10 != 0) {
    ShowBlockingWaitOverlayDialog();
    this->field10 = 0;
  }
  this->currentTurnEventCode = newCode;

  if (newCode > kTurnEventMapEditor) {
    if (newCode < kTurnEventRandomGameSetup) {
      if (newCode == kTurnEventMainMenu) {
        this->HandleTurnEventDialogFactorySlotF8();
      } else if (newCode == kTurnEventDiplomacyOffer) {
        this->SetCursorRangeAndRefreshMainPanel(static_cast<int>(newCode));
      }
    } else if (newCode < kTurnEventTradeOverview) {
      switch (newCode) {
      case kTurnEventRandomGameSetup:
        this->NoOpTurnEventStateVtableSlotFC();
        break;
      case kTurnEventLoadSave:
        this->HandleTurnEvent5DE_RefreshMainView();
        break;
      case kTurnEventScenarioGameSetup:
        this->HandleTurnEvent5DF_RefreshMainView();
        break;
      case kTurnEventHighScores:
        this->RefreshMainViewForTurnEvent5DF();
        break;
      case kTurnEventDiplomacyMap:
        this->HandleTurnEvent7D8_ActivateDiplomacyMapView(newCode);
        g_pGlobalUiRootController->dispatchBusyFlag4c = 1;
        break;
      }
    } else if (newCode > kTurnEventTechnologyAdvance) {
      if (newCode == kTurnEventTacticalView || newCode == kTurnEventProvisional0F3C) {
        this->SyncTacticalStatusPanelRegion();
      } else if (newCode == kTurnEventTechnologyStore) {
        this->RefreshTechnologyStorePageAndHudText(0);
      } else if (newCode == kTurnEventOpeningCinematic) {
        this->HandleTurnEventDialogFactorySlotF4();
      } else if (newCode == kTurnEventUnitHistory) {
        this->ShowUnitHistory(secondary);
      } else if (newCode == kTurnEventNewspaperStatus) {
        this->HandleTurnEvent2103_RunNationStatusReportUpdate(secondary);
      } else if (newCode == kTurnEventOfferSheet) {
        this->RefreshMainDialogAndCursorHelp(newCode);
      } else if (newCode == kTurnEventDealBook) {
        this->HandleTurnEvent2260_RefreshMainHudTitles(newCode);
      }
    } else if (newCode == kTurnEventTechnologyAdvance) {
      this->ShowAbilityStatusReport(secondary);
    } else {
      switch (newCode) {
      case kTurnEventTradeOverview:
      case kTurnEventIndustryOverview:
        this->HandleTurnEvent7D9Or7DA_UpdateNationResourceAdvisor(secondary);
        g_pGlobalUiRootController->dispatchBusyFlag4c = 1;
        break;
      case kTurnEventCityProduction:
        this->HandleTurnEvent7DB_SelectCityAndRefreshView(secondary);
        g_pGlobalUiRootController->dispatchBusyFlag4c = 1;
        break;
      case kTurnEventStrategicMap:
        this->HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(newCode);
        break;
      case kTurnEventTransport:
        this->HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary(newCode);
        break;
      case kTurnEventCouncilOfGovernors:
        this->SetCursorRangeAndRefreshMainPanel(static_cast<int>(secondary));
        break;
      }
    }
  } else if (newCode == kTurnEventMapEditor) {
    this->ConfigureActiveDialogGoldValueGridForTurnEvent3C0();
    g_pGlobalUiRootController->dispatchBusyFlag4c = 0;
  } else if (newCode == kTurnEventCitySiteSelector) {
    this->InitializeCitySiteSelectionScreenForNation(static_cast<int>(secondary));
    g_pGlobalUiRootController->dispatchBusyFlag4c = 0;
  }
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTestDriver::ObserveActivatedTurnEvent(newCode);
#endif
  DispatchPostTurnStateUpdatesTail();
}

// FUNCTION: IMPERIALISM 0x005d7c40
void TViewMgr::DispatchTurnEvent3B8AndWaitForCompletion(int payload, TEventHandler* waitTarget) {
  DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCitySiteSelector), payload);
  while (static_cast<short>(waitTarget->field14) == 0) {
    if (PumpUiMessagesAndBackgroundTasks(1) == 0) {
      g_pGlobalUiRootController->PostWmCloseToMainThreadWindow();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005d7cb0
void TViewMgr::HandleTurnEvent7DB_SelectCityAndRefreshView(int nationSlot) {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  TView* mainView = turn_event_ui_refresh::ActiveMainView();
  if (mainView == nullptr) {
    return;
  }

  TControl* cityControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagCity));
  if (cityControl != nullptr) {
    cityControl->AssertValid();
    cityControl->SetState(0, 0);
    cityControl->SwitchActiveChildAndNotify(nullptr);
    cityControl->SetHoverHelpText(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTopB);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagQuer));
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->SetHoverHelpText(g_szEmptyString);
  }

  TCityProductionView* productionView =
      static_cast<TCityProductionView*>(mainView->ResolveControlByTag(kControlTagMain));
  productionView->AssertValid();
  productionView->SetHoverHelpText(g_szEmptyString);
  g_pStrategicMapViewSystem->activeCityProductionView04 = productionView;

  TGreatPower* nation = g_apNationStates[static_cast<short>(nationSlot)];
  TCity* city = nation != nullptr ? nation->city : nullptr;
  productionView->InitializeCityProductionDialog(city, mainView);
}

// FUNCTION: IMPERIALISM 0x005d7f70
void TViewMgr::RefreshCityProductionUi() {
  g_pStrategicMapViewSystem->RefreshActiveCityBuildingActionAvailabilityIndicators();
}

// FUNCTION: IMPERIALISM 0x005d7f90
void TViewMgr::ClearActiveCityBuildingViewSlot(short param1) {
  g_pStrategicMapViewSystem->ClearActiveCityBuildingViewSlot(param1);
}

// FUNCTION: IMPERIALISM 0x005d7fc0
void TViewMgr::SetCursorRangeAndRefreshMainPanel(int payload) {
  (void)payload;
  TView* mainView = g_pDisplayMgr->activeDialog;
  TControl* cursor = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel = static_cast<TInfoBarText*>(cursor);
  cursor->AssertValid();
  static_cast<TInfoBarText*>(cursor)->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
  TControl* mainPanel = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagMain));
  mainPanel->AssertValid();
  static_cast<TCouncilView*>(static_cast<void*>(mainPanel))
      ->InitializeDiplomacyCouncilViewControlsAndTicker();
}

// FUNCTION: IMPERIALISM 0x005d8040
void TViewMgr::HandleTurnEvent7D8_ActivateDiplomacyMapView(int) {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  TView* mainView = turn_event_ui_refresh::ActiveMainView();
  if (mainView == nullptr) {
    return;
  }

  TControl* diplControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagDipl));
  if (diplControl != nullptr) {
    diplControl->AssertValid();
    diplControl->SetState(0, 0);
    diplControl->SwitchActiveChildAndNotify(nullptr);
    diplControl->SetHoverHelpText(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTopB);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagQuer));
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->SetHoverHelpText(g_szEmptyString);
  }

  if (diplControl != nullptr) {
    diplControl->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005d83b0
void TViewMgr::HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary(int) {
  turn_event_ui_refresh::RefreshMainPanelControl();
  g_pSimMgr->SetFlags(0x1000);
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();

  TControl* tranControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTran);
  if (tranControl != nullptr) {
    tranControl->AssertValid();
    tranControl->SetState(0, 0);
    tranControl->SwitchActiveChildAndNotify(nullptr);
    tranControl->SetHoverHelpText(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTopB);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagQuer);
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->SetHoverHelpText(g_szEmptyString);
  }
}

// FUNCTION: IMPERIALISM 0x005d8750
void TViewMgr::RefreshTechnologyStorePageAndHudText(int nationSlot) {
  TView* mainView = g_pDisplayMgr->activeDialog;

  TTechStorePage* page =
      static_cast<TTechStorePage*>(mainView->ResolveControlByTag(kControlTagPage));
  page->AssertValid();
  page->PopulateUnlockedTechnologyRows(nationSlot);

  TToolBarCluster* toolbar =
      static_cast<TToolBarCluster*>(mainView->ResolveControlByTag(kControlTagTool));
  toolbar->AssertValid();
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetActiveNationId());
  toolbar->RefreshTurnOrderStatusPanelTextsAndControls();

  g_pCursorControlPanel =
      static_cast<TInfoBarText*>(mainView->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  toolbar = static_cast<TToolBarCluster*>(mainView->ResolveControlByTag(kControlTagTopB));
  toolbar->AssertValid();
  toolbar->RefreshTurnOrderStatusPanelTextsAndControls();

  for (int titleIndex = 0; titleIndex < 3; ++titleIndex) {
    CString title;
    TDropShadowText* titleControl = static_cast<TDropShadowText*>(
        mainView->ResolveControlByTag(kControlTagTtl1 + titleIndex)); // 'ttl1'..'ttl3'
    titleControl->AssertValid();
    ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0xe, 0x2b6a, 0x2b68);
    g_pSimMgr->GetString(0x274f, static_cast<short>(titleIndex + 4), &title);
    titleControl->SetTextAndMaybeRefresh(&title, 1);
  }

  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagPage);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 0xd, kControlTagEnd);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 3, kControlTagQuer);
}

// FUNCTION: IMPERIALISM 0x005d8980
void TViewMgr::ShowAbilityStatusReport(int abilityIndex) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TextStyle style;
  char* styleRefBytes = reinterpret_cast<char*>(&style.textColor);
  styleRefBytes[0] = 0;
  styleRefBytes[1] = 0;
  styleRefBytes[2] = 0;
  styleRefBytes[3] = 0;
  CString statusText;
  CString prefix;
  TPicture* mainControl =
      static_cast<TPicture*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();

  TControl* queryControl =
      static_cast<TControl*>(activeDialog->ResolveControlByTag(kControlTagQuer));
  if (queryControl != 0) {
    g_pSimMgr->GetString(0x2730, 2, &statusText);
    SetControlHoverHelpText(statusText, queryControl);
  }

  TControl* toolControl =
      static_cast<TControl*>(activeDialog->ResolveControlByTag(kControlTagTool));
  toolControl->AssertValid();
  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(toolControl);
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetActiveNationId());
  toolbar->RefreshTurnOrderStatusPanelTextsAndControls();

  g_pCursorControlPanel =
      static_cast<TInfoBarText*>(activeDialog->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  short pictureResourceId = static_cast<short>(
      g_anAbilityStatusPictureIndex_0066F058[static_cast<short>(abilityIndex)] + 0x897);
  mainControl->SetPictureResourceIdAndRefresh(pictureResourceId, true);

  TDeluxeText* textControl =
      static_cast<TDeluxeText*>(activeDialog->ResolveControlByTag(kControlTagText));
  textControl->AssertValid();
  g_pSimMgr->GetString(0x274e, abilityIndex - 1, &prefix);
  g_pSimMgr->GetString(0x2712, abilityIndex, &statusText);
  statusText += '\r';
  statusText += '\r';
  statusText += prefix;
  textControl->SetTextAndMaybeRefresh(&statusText, 1);

  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6b);
  textControl->InstallTextStyle(style, 0);
  textControl->SetTextAlignmentAndMaybeRefresh(-2, 0);
  activeDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005d8c40
void TViewMgr::HandleTurnEvent2103_RunNationStatusReportUpdate(int pageIndex) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TNewspaperView* mainControl =
      static_cast<TNewspaperView*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();
  g_pSfxPlaybackSystem->PlaySoundEffect(0x14b4, 0, 1);
  mainControl->BuildInterNationEventSummaryRowsForAdvisorDialog(pageIndex);
  activeDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005d8cc0
void TViewMgr::SyncTacticalStatusPanelRegion() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CTemporaryRegion temporaryRegion;
  TTacticalBattleView* goldControl =
      static_cast<TTacticalBattleView*>(activeDialog->ResolveControlByTag(kControlTagDialog));
  goldControl->AssertValid();
  goldControl->SyncStatusPanelBounds();

  // The tactical view's owner is the tactical map picture, a TOffLimitsPicture
  // subclass, so byte 0x1cc is its ForwardCopyRgn.
  TOffLimitsPicture* owner = static_cast<TOffLimitsPicture*>(goldControl->ownerContext);
  owner->AssertValid();

  CRect bounds;
  goldControl->QueryBounds(&bounds);
  RECT regionBounds = bounds;
  RectRgn(temporaryRegion.tempRgn, &regionBounds);

  owner->ForwardCopyRgn(temporaryRegion.tempRgn);
}

// FUNCTION: IMPERIALISM 0x005d8dd0
void TViewMgr::HandleTurnEvent7D9Or7DA_UpdateNationResourceAdvisor(int nationIndex) {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  turn_event_ui_refresh::RefreshTradClusterPictureAndHintText();

  TToolBarCluster* topToolbar = static_cast<TToolBarCluster*>(
      turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTopB));
  topToolbar->AssertValid();
  topToolbar->RefreshTurnOrderStatusPanelTextsAndControls();

  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(
      turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTool));
  toolbar->AssertValid();
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(static_cast<short>(nationIndex));
  toolbar->RefreshTurnOrderStatusPanelTextsAndControls();

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagQuer, 0x2730, 2);

  TControl* mainControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagMain);
  mainControl->AssertValid();
  mainControl->SetHoverHelpText(g_szEmptyString);

  TGreatPower* nation = g_apNationStates[static_cast<short>(nationIndex)];
  g_pSimMgr->SetFlags(0x100);
  nation->RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix();
  this->fieldEc = 0;
  for (short metricSlot = 0; metricSlot < 0x11; ++metricSlot) {
    if (nation->QueryNationMetricBySlot7C(metricSlot) == -1) {
      this->fieldEc = static_cast<short>(this->fieldEc + 1);
    }
  }

  const unsigned int kTagTopTitle = IMPERIALISM_FOURCC('t', 'o', 'p', 'T');
  const unsigned int kTagCommodityTitle = IMPERIALISM_FOURCC('c', 'o', 'm', 'T');
  const unsigned int kTagOrdersTitle = IMPERIALISM_FOURCC('o', 'r', 'd', 'T');
  const unsigned int kTagPriceTitle = IMPERIALISM_FOURCC('p', 'r', 'i', 'T');
  const unsigned int kTagAvailableTitle = IMPERIALISM_FOURCC('a', 'v', 'a', 'T');
  const unsigned int kTagQuantityTitle = IMPERIALISM_FOURCC('q', 't', 'y', 'T');
  const unsigned int kTagMiniPicture = IMPERIALISM_FOURCC('m', 'P', 'i', 'c');

  CString label;
  TDropShadowText* title =
      static_cast<TDropShadowText*>(turn_event_ui_refresh::ResolveMainTaggedControl(kTagTopTitle));
  title->AssertValid();
  ApplyUiTextStyleAndThemeFlags(title, 0, 0x10, 0x2b6c, 0x2b67);
  g_pSimMgr->GetString(0x2731, 0xc, &label);
  title->SetTextAndMaybeRefresh(&label, 0);

  TDropShadowText* commodityTitle = static_cast<TDropShadowText*>(
      turn_event_ui_refresh::ResolveMainTaggedControl(kTagCommodityTitle));
  commodityTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(commodityTitle, 0, 0xc, 0x2b6c, 0x2b67);
  g_pSimMgr->GetString(0x2731, 0xd, &label);
  commodityTitle->SetTextAndMaybeRefresh(&label, 0);

  TDropShadowText* ordersTitle = static_cast<TDropShadowText*>(
      turn_event_ui_refresh::ResolveMainTaggedControl(kTagOrdersTitle));
  ordersTitle->AssertValid();
  ApplyUiTextStyleAndThemeFlags(ordersTitle, 0, 0xc, 0x2b6c, 0x2b67);
  g_pSimMgr->GetString(0x2731, 0xe, &label);
  ordersTitle->SetTextAndMaybeRefresh(&label, 0);

  TextStyle columnStyle;
  BuildUiTextStyleDescriptor(&columnStyle, 0, 0xc, 0x2b68);
  const unsigned int columnTags[3] = {kTagPriceTitle, kTagAvailableTitle, kTagQuantityTitle};
  for (short column = 0; column < 3; ++column) {
    TStaticText* columnTitle = static_cast<TStaticText*>(
        turn_event_ui_refresh::ResolveMainTaggedControl(columnTags[column]));
    columnTitle->AssertValid();
    columnTitle->InstallTextStyle(columnStyle, 0);
    g_pSimMgr->GetString(0x2731, static_cast<short>(0xf + column), &label);
    columnTitle->SetTextAndMaybeRefresh(&label, 0);
  }

  TView* miniPicture = turn_event_ui_refresh::ResolveMainTaggedControl(kTagMiniPicture);
  miniPicture->AssertValid();
  g_pSimMgr->GetString(0x2731, 3, &label);
  miniPicture->SetHoverHelpText(label);

  TDropShadowNumberText* capacity = static_cast<TDropShadowNumberText*>(
      turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagMCap));
  if (capacity == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x686);
  }
  capacity->AssertValid();
  ApplyUiNumberTextStyleAndThemeColor(capacity, 0, 0xa, 0x2b6c, 0x2b67);
  capacity->HiliteState(1, 0);
  capacity->SetControlValue(nation->tradeCapacity, 0);

  TCity* city = nation->city;
  if (city == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x697);
  }
  short* citySummary = city->GetCitySummaryRecordSlot74();

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

  TView* food = turn_event_ui_refresh::ResolveMainTaggedControl(kTagFood);
  if (food == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x6ad);
  }
  const int foodOnHand =
      city->cityStockCannedFoodC4 + city->cityStockLivestockDE + city->cityStockGrainD8 +
      city->cityStockFruitDA + nation->needTargetByType[kResourceLivestock] +
      nation->needTargetByType[kResourceFruit] + nation->needTargetByType[kResourceFish] +
      nation->needTargetByType[kResourceGrain];
  const int foodRequired =
      citySummary[kResourceLivestock] + citySummary[kResourceFruit] + citySummary[kResourceGrain];
  const bool foodShortage = foodOnHand < foodRequired;
  food->SetEnabled(foodShortage ? 1 : 0, 0);
  g_pSimMgr->GetString(0x2731, foodShortage ? 4 : 8, &label);
  food->SetHoverHelpText(label);

  TView* cotton = turn_event_ui_refresh::ResolveMainTaggedControl(kTagCotton);
  TView* wool = turn_event_ui_refresh::ResolveMainTaggedControl(kTagWool);
  const bool textileShortage = city->cityStockCottonB6 + city->cityStockWoolB8 +
                                   nation->needTargetByType[kResourceCotton] +
                                   nation->needTargetByType[kResourceWool] <
                               city->GetBuildingType(0) * 2;
  g_pSimMgr->GetString(0x2731, 0x13, &label);
  cotton->SetEnabled(textileShortage ? 1 : 0, 0);
  wool->SetEnabled(textileShortage ? 1 : 0, 0);
  cotton->SetHoverHelpText(textileShortage ? label : CString(g_szEmptyString));
  wool->SetHoverHelpText(textileShortage ? label : CString(g_szEmptyString));

  struct ShortageControl {
    unsigned int tag;
    short stock;
    short needType;
    short buildingType;
    short multiplier;
    short stringIndex;
  };
  const ShortageControl shortageControls[7] = {
      {kTagTimber, city->cityStockTimberBA, kResourceTimber, 4, 2, 0x15},
      {kTagCoal, city->cityStockCoalBC, kResourceCoal, 2, 1, 0x16},
      {kTagIron, city->cityStockIronBE, kResourceIron, 2, 1, 0x17},
      {kTagOil, city->cityStockOilC2, kResourceOil, 6, 2, 0x18},
      {kTagFabric, city->cityStockFabricC6, kResourceFabric, 1, 2, 0x19},
      {kTagLumber, city->cityStockLumberC8, kResourceLumber, 5, 2, 0x1a},
      {kTagSteel, city->cityStockSteelCC, kResourceSteel, 3, 2, 0x1b}};
  for (short i = 0; i < 7; ++i) {
    TView* shortageControl =
        turn_event_ui_refresh::ResolveMainTaggedControl(shortageControls[i].tag);
    const bool shortage =
        shortageControls[i].stock + nation->needTargetByType[shortageControls[i].needType] <
        city->GetBuildingType(shortageControls[i].buildingType) * shortageControls[i].multiplier;
    shortageControl->SetEnabled(shortage ? 1 : 0, 0);
    if (shortage) {
      g_pSimMgr->GetString(0x2731, shortageControls[i].stringIndex, &label);
      shortageControl->SetHoverHelpText(label);
    } else {
      shortageControl->SetHoverHelpText(g_szEmptyString);
    }
  }

  if (nation->tradeCapacity == 0) {
    g_pSimMgr->GetString(0x2731, 0x12, &label);
    ModalMessage(label, g_ptCitySiteSelectionDialogPlacement);
    this->fieldEc = 5;
  }

  for (short commodity = 0; commodity < 0x11; ++commodity) {
    TView* row = turn_event_ui_refresh::ActiveMainView()->ResolveControlByTag(
        g_tradeCommodityRowTagTable[commodity]);
    if (row == nullptr) {
      continue;
    }
    g_pStrategicMapViewSystem->SyncSellTaggedChildControlWithNationState(
        row, commodity, static_cast<short>(nationIndex));
    if ((commodity == 6 || commodity == 0xc) &&
        g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] == 0) {
      row->Free();
    } else {
      g_pSimMgr->GetStringPrelude(commodity, &label);
      row->SetHoverHelpText(label);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005da040
void TViewMgr::RefreshMainDialogAndCursorHelp(int) {
  TView* mainControl =
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();
  mainControl->RefreshControl();

  g_pCursorControlPanel = static_cast<TInfoBarText*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagCurs)));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  CString emptyTitle(g_szEmptyString);
  SetControlHoverHelpText(emptyTitle, mainControl);
}

// FUNCTION: IMPERIALISM 0x005da180
void TViewMgr::HandleTurnEvent2260_RefreshMainHudTitles(int) {
  TView* mainView = g_pDisplayMgr->activeDialog;

  g_pCursorControlPanel =
      static_cast<TInfoBarText*>(mainView->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  TView* mainControl = static_cast<TView*>(mainView->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();
  CString emptyTitle(g_szEmptyString);
  SetControlHoverHelpText(emptyTitle, mainControl);

  TView* queryControl = mainControl->ResolveControlByTag(kControlTagQuer);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, queryControl);

  TControl* titleControl =
      static_cast<TControl*>(mainControl->ResolveControlByTag(kControlTagTitL)); // 'titL'
  if (titleControl != nullptr) {
    titleControl->AssertValid();
    titleControl->RefreshControl();
    static_cast<TInfoBarText*>(titleControl)
        ->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b6b);
    CString titleString;
    g_pSimMgr->GetString(0x2741, 0, &titleString);
    titleControl->SetHoverHelpText(titleString);
  }
  // 0x5bac50 is invoked on the 'main' deal-book control (the binary's receiver), not 'titL'.
  static_cast<TDealBookPicture*>(mainControl)->Startup(0x2b6c);
}

// FUNCTION: IMPERIALISM 0x005da360
void TViewMgr::HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(int) {
  const short activeNationId = g_pSimMgr->GetActiveNationId();
  if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(activeNationId) == 0) {
    g_pSimMgr->SetFlags(static_cast<unsigned int>(-1));
  }

  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTbr1);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagDipl, 1, 0x24d9, 0x24e1);
  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagTrad, 0x100, 0x24db, 0x24e3);
  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagCity, 0x10, 0x24dd, 0x24e5);
  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagTran, 0x1000, 0x24df, 0x24e7);

  TControl* tranControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTran);
  if (tranControl != nullptr) {
    tranControl->AssertValid();
    g_pSimMgr->TestTurnFlowStatusFlagMask(0x1000);
    const short followUpPictureId = g_pSimMgr->TestTurnFlowStatusFlagMask(0x1000) ? 0x24df : 0x24e7;
    static_cast<TPicture*>(tranControl)->SetPictureResourceIdAndRefresh(followUpPictureId, true);
  }

  turn_event_ui_refresh::RefreshQuerControlLayoutAndClearText();

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagQuer, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagCity, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagTrad, 0x2730, 0);

  if (g_pSimMgr->TestTurnFlowStatusFlagMask(1) == 0) {
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagDipl, 0x19, 0);
  } else {
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagDipl, 0x15, 0);
  }

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagTran, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagCity, 0x2731, 0);
}

// FUNCTION: IMPERIALISM 0x005db3b0
void TViewMgr::HandleTurnEventDialogFactorySlotF4() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TMovieView* movieView =
      static_cast<TMovieView*>(activeDialog->ResolveControlByTag(kControlTagMovi));
  movieView->AssertValid();
  movieView->SetState(1, 0);
  movieView->ForceRedraw();

  CString movieName;
  switch (g_pSimMgr->mode) {
  case 1:
    movieName = CString("open");
    if (movieView->linkedChildHandler != 0) {
      static_cast<TView*>(movieView->linkedChildHandler)->SetState(0, 0);
    }
    break;
  case 0xe:
    movieName = CString("vote");
    break;
  case 0x16:
    movieName = CString("win");
    break;
  case 0x17:
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(g_pSimMgr->GetActiveNationId())) {
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
    g_pUiViewManager->PlayMovieClipAndDispatchTurnStateFollowup(movieName, movieView);
  }
}

namespace {
// Shared by each main-menu button: resolve by tag, assert (msgbox + one-shot invalidation-flag
// clear if missing, matching the sibling null-check blocks elsewhere in this file), fetch the
// button's localized label from g_pSimMgr's string table, and apply it.
void RefreshMainMenuButtonLabel(TView* mainView, unsigned int controlTag, short codeGroup,
                                short stringIndex, int assertLine) {
  TControl* control = static_cast<TControl*>(mainView->ResolveControlByTag(controlTag));
  if (control == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, assertLine);
  }
  CString label;
  g_pSimMgr->GetString(codeGroup, stringIndex, &label);
  control->SetHoverHelpText(label);
}
} // namespace

// Screen-exit backbone: record the followup turn state; when leaving (state 0),
// re-apply the audio volume preferences and post the followup turn-event code for the
// current TSimMgr mode (1 -> 0x5dc main menu, 0xe/0x16/0x17 -> 0x7e0,
// 0x19 -> 0x5eb when the active nation is eligible, else reinitialize).
// FUNCTION: IMPERIALISM 0x005db620
void TViewMgr::HandleTurnStateExitAndPostFollowupEventCode(short followupState) {
  this->fieldF8 = followupState;
  if (followupState != 0) {
    return;
  }
  g_pSfxPlaybackSystem->RequestDirectSoundInitIfAllowed();
  g_pSfxPlaybackSystem->SetMasterVolumeFromPercent(g_pSimMgr->preferenceValues[2]);
  g_pSfxPlaybackSystem->ScaleAndApplyAuxOutputVolume(g_pSimMgr->preferenceValues[3]);
  this->activeMovieViewF4 = 0;
  switch (g_pSimMgr->mode) {
  case 1:
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventMainMenu));
    return;
  case 0xe:
  case 0x16:
  case 0x17:
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventCouncilOfGovernors));
    return;
  case 0x19:
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(g_pSimMgr->GetActiveNationId())) {
      g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
          EncodeTurnEventCode(kTurnEventGameScore));
      return;
    }
  default:
    ReinitializeGameFlowAndPostTurnEventCode(kTurnEventRebuildRegisteredWindows);
  }
}

// Main-menu screen setup (turn-event 0x5dc): resets the background-music cue pools, then
// configures the 'curs' cursor-info panel's style/theme and finally sets every menu button's
// localized label (the 'main' council-ticker slot is cleared instead of labeled).
// FUNCTION: IMPERIALISM 0x005db780
void TViewMgr::HandleTurnEventDialogFactorySlotF8() {
  TView* mainView = g_pDisplayMgr->activeDialog;

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(6);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();

  g_pCursorControlPanel = nullptr;
  g_pCursorControlPanel =
      static_cast<TInfoBarText*>(mainView->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();

  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);

  TextStyle styleDescriptor = {0, 0, 0, 0};
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xe, 0x2b6c);
  g_pCursorControlPanel->SetTextStyle(styleDescriptor, 1);
  g_pCursorControlPanel->SetTextAlignmentAndMaybeRefresh(1, 0);

  COLORREF mappedStyleFlags = 0;
  ResolveUiThemeColor(0x2b6b, &mappedStyleFlags);
  g_pCursorControlPanel->shadowTextColor9C = mappedStyleFlags;
  g_pCursorControlPanel->dropShadowEnabledA0 = true;

  // 'main' (council ticker) is not null-checked in the original, unlike the buttons below.
  TControl* mainControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();
  CString emptyString(g_szEmptyString);
  mainControl->SetHoverHelpText(emptyString);

  RefreshMainMenuButtonLabel(mainView, kControlTagRand, 0x2737, 0, 0xdf0);
  RefreshMainMenuButtonLabel(mainView, kControlTagLoad, 0x2737, 1, 0xdf9);
  RefreshMainMenuButtonLabel(mainView, kControlTagMult, 0x2737, 2, 0xdfe);
  RefreshMainMenuButtonLabel(mainView, kControlTagHigh, 0x2737, 3, 0xe03);
  RefreshMainMenuButtonLabel(mainView, kControlTagScen, 0x2737, 4, 0xe08);
  RefreshMainMenuButtonLabel(mainView, kControlTagQuit, 0x2737, 9, 0xe0d);
  RefreshMainMenuButtonLabel(mainView, kControlTagPref, 0x2743, 8, 0xe12);
}

// FUNCTION: IMPERIALISM 0x005dbd10
void TViewMgr::NoOpTurnEventStateVtableSlotFC() {}

// Turn-event 0x5DE (vtable slot 0x100): like the 0x5DF handler, re-asserts and refreshes the
// 'main' view panel; the original brackets the body with a scoped (empty) CString local.
// FUNCTION: IMPERIALISM 0x005dbd30
void TViewMgr::HandleTurnEvent5DE_RefreshMainView() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CString scratch;
  TView* mainView = activeDialog->ResolveControlByTag(kControlTagMain);
  mainView->AssertValid();
  mainView->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005dbdd0
void TViewMgr::HandleTurnEvent5DF_RefreshMainView() {
  TView* mainPanel = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
  mainPanel->AssertValid();
  mainPanel->RefreshControl();
}

// Twin of HandleTurnEvent5DF_RefreshMainView: re-assert and refresh the active dialog's
// 'main' council-ticker panel.
// FUNCTION: IMPERIALISM 0x005dbe10
void TViewMgr::RefreshMainViewForTurnEvent5DF() {
  TView* mainPanel = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
  mainPanel->AssertValid();
  mainPanel->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005dc160
void TViewMgr::RefreshActiveGoldControlAndUiRuntimeState() {
  g_pStrategicMapViewSystem->RefreshActiveGoldControlAndUiRuntimeState();
}

// FUNCTION: IMPERIALISM 0x005dc180
void TViewMgr::ForwardBuildStrategicMapRenderAtlasesAndTileMaskCaches() {
  g_pStrategicMapViewSystem->BuildStrategicMapRenderAtlasesAndTileMaskCaches();
}

// FUNCTION: IMPERIALISM 0x005dc1a0
void TViewMgr::RebuildMapTileNeighborHighlightPolygonsForAllTiles() {
  g_pStrategicMapViewSystem->RebuildMapTileNeighborHighlightPolygonsForAllTiles();
}

// FUNCTION: IMPERIALISM 0x005dc1c0
void TViewMgr::RenderTurnEventPalettePreviewSurfaceAndProgress() {
  g_pStrategicMapViewSystem->RenderTurnEventPalettePreviewSurfaceAndProgress();
}

// FUNCTION: IMPERIALISM 0x005dc1e0
void TViewMgr::InitializeCitySiteSelectionScreenForNation(int nationSlot) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;

  TToolBarCluster* toolbar =
      static_cast<TToolBarCluster*>(activeDialog->ResolveControlByTag(kControlTagTool));
  toolbar->AssertValid();
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(static_cast<short>(nationSlot));

  TCitySiteView* citySiteView =
      static_cast<TCitySiteView*>(activeDialog->ResolveControlByTag(kControlTagDialog));
  citySiteView->AssertValid();
  g_pGlobalMapState->SeedValidCitySiteCandidateTilesForNation(static_cast<short>(nationSlot));
  TGreatPower* nation = g_apNationStates[static_cast<short>(nationSlot)];
  TCity* city = nation != nullptr ? nation->city : nullptr;
  citySiteView->pendingTown364 = static_cast<TTown*>(city->selectedOrderB0);
  citySiteView->SetMapViewTileIndex(
      g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(nationSlot));

  TMapUberPicture* mainPicture =
      static_cast<TMapUberPicture*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainPicture->AssertValid();
  mainPicture->DisplayMiniMap();

  CString formatText;
  CString messageText;
  g_pSimMgr->GetString(0x273f, 4, &formatText);
  g_pSimMgr->GetString(0x273f, 3, &messageText);
  ModalMessage(4, formatText, messageText, g_ptCitySiteSelectionDialogPlacement, 2, 0);
}

// FUNCTION: IMPERIALISM 0x005dc3f0
void TViewMgr::ConfigureActiveDialogGoldValueGridForTurnEvent3C0() {
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(static_cast<TView*>(
      g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagDialog))); // 'GOLD'
  gold->AssertValid();
  gold->ConfigureGoldValueCells(0x14, 0x14);
}

// FUNCTION: IMPERIALISM 0x005dc430
void TViewMgr::ShowBuildingExpansionDialog(short buildingSlotId, TCity* city,
                                           TCityProductionView* productionView) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGenericExpander));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0xf50);
  }
  node->SetModality(1);
  // MapView.rsrc view 9221's 'DLOG' pict is a TBuildingExpansionView (Mac resource
  // oracle), whose slots 0x73/0x74 are StuffValues and DoClosingAction.
  TBuildingExpansionView* expansionView =
      static_cast<TBuildingExpansionView*>(node->ResolveControlByTag(kControlTagDialog)); // 'DLOG'
  expansionView->AssertValid();
  if (expansionView == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0xf54);
  }
  expansionView->StuffValues(buildingSlotId, city, productionView);
  CPoint placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->Locate(placement, 0);
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
      static_cast<TToolBarCluster*>(activeDialog->ResolveControlByTag(kControlTagTool));
  toolbar->AssertValid();
  if (toolbar != 0) {
    toolbar->UpdateControlTagTreaTextFromNationAndMapContext(nationSlot);
  }

  TSortedByRelationshipList* history = g_apNationStates[nationSlot]->turnSummaryQueue;
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
    lineText = s_szTurnHistoryPrefix_0069b71c + lineText + s_szTurnHistorySeparator_00699320;
    lineText += countText + s_szSpaceSeparator_00695794 + messageText;

    // Mac Transport.rsrc:3901 identifies the twenty history labels as the
    // consecutive FourCC tags `txtA`..`txtT`.
    TStaticText* textControl = static_cast<TStaticText*>(
        activeDialog->ResolveControlByTag(kControlTagTxtAt + entryOrdinal));
    if (textControl != 0) {
      textControl->SetEnabled(1, 1);
      textControl->SetTextAndMaybeRefresh(&lineText, 1);
    }

    ++entryOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x005dcaa0
void TViewMgr::MakeGameSetupDialog() {
  TA1TemplateDialog dialog(NULL);

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
