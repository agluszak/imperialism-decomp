#include "game/TViewMgr.h"
#include "game/TC2TemplateDialog.h"
#include "game/TEventHandler.h"

#include "game/TDealBookPicture.h"
#include "game/TModuleLibraryCacheTableStateB.h"

#include "game/turn_event_dialog_provisional.h"

#include "game/ImperialismApp.h"
#include "game/TAmbitApplication.h"
#include "game/TAssetMgr.h"
#include "game/TSoundPlayer.h"        // g_pSfxPlaybackSystem
#include "game/TMacViewMgr.h"         // g_pStrategicMapViewSystem
#include "game/TIncludeView.h"        // turn-event UI entry packet ('Incl')
#include "game/CWMgrIterator.h"       // window-registry traversal for the full (code-0) refresh
#include "game/quickdraw_rendering.h" // SetQuickDrawFillColor / SetQuickDrawStrokeColor
#include "game/TToolBarCluster.h"     // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/TMovieView.h"

#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TCivToolbar.h"
#include "game/global_data_tables.h" // g_pGameFlowState, g_pSimMgr, g_apNationStates
#include "game/TCountry.h"           // FormatOverlayTerrainLabelText (terrain overlay case)
#include "game/TGreatPower.h"
#include "game/TGarrisonView.h"
#include "game/TGlobalMapState.h"
#include "game/TDisplayMgr.h" // g_pDisplayMgr, g_szUiNilPointerMessage, g_szUiFailureMessage
#include "game/THelpMgr.h"
#include "game/TWindow.h"
#include "game/ui_control_tags.h"
#include "game/TInfoBarText.h"
#include "game/TCouncilTickerAnimation.h"
#include "game/TCouncilView.h"
#include "game/CTemporaryRegion.h"
#include "game/TNewspaperView.h"
#include "game/TToolBarCluster.h"
#include "game/TPicture.h"
#include "game/nation_slot_eligibility.h"
#include "game/turn_flow_cooldown.h" // IsTurnCooldownCounterActiveOrResetFlag
#include "game/ui_invalidation_guard.h"
#include "game/TMultiplayerMgr.h"
#include "game/TCluster.h"
#include "game/TDiplomacyMapView.h"
#include "game/TModalMessageCommand.h"
#include "game/TApplication.h"
#include "game/TSuperCivRoster.h"
#include "game/TTacticalBattleView.h"
#include "game/TScrollView.h" // nation-info modal overflow scroll wrapper
#include "game/TStaticText.h"
#include "game/mapped_flavor_text.h" // BuildUiMessageTextFromBracketTemplate / scanBracketExpressions
#include "game/TEditText.h"
#include "game/TRadioText.h"
#include "game/TRadioTextCluster.h"
#include "game/TDeluxeText.h"
#include "game/TCivMgr.h"
#include "game/TCivUnit.h"
#include "game/TMapUberPicture.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/quickdraw_rendering.h" // ApplyControlThemeStyleAndOptionalCaption
#include "game/ui_text_label_helpers_decls.h"

undefined4 ShowDialogTemplateE0ModalAndReleaseCapture(void);
undefined4 HandleTurnEvent8FC_RebuildPageTabsAndTitles(void);

#include <new>

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pSimMgr / turn-state
// manager). Included via global_data_tables.h.

// The display/GWorld manager (g_pDisplayMgr @ 0x6a2158); its activeDialog (+0x04) field
// holds the active main TView used as the dispatch root for turn-event UI refreshes.

#include "game/CIncludeView.h"

// The former RunNationInfoModalAndReturnNonCancel / NoOpUiRuntimeCallback_005db2f0 /
// NoOpRuntimeCallback_005d5d10 extern bridges are gone: the modal is a real TViewMgr
// method now, and the two "NoOp" callbacks were mis-named out-of-line COMDAT copies of
// CString::GetLength / CString::GetPchData that the tail call sites use via the real
// CString API.

// Provisional dispatch interfaces for the runtime-resolved turn-event dialog node and
// its 'GOLD' child control now live in one shared header so the TViewMgr and
// TMacViewMgr copies can't drift apart (bd imperialism-decomp-hpd.7). The lower slots
// (ResolveControlByTag, CaptureLayoutF0, Close, Free, AssertValid) are real
// inherited TView/TObject virtuals dispatched directly.
namespace {
using turn_event_dialog::GoldCommitControl;
using turn_event_dialog::GoldDialogControl;
using turn_event_dialog::GoldFactoryPanel;
using turn_event_dialog::TCivilianReportGoldControl;
using turn_event_dialog::TurnEventDialogNode;
// g_pUiViewManager (TAssetMgr) @ 0x6a2148 — the UI/view asset registry that resolves
// turn-event dialog nodes by message context.
const unsigned int kAddrDefaultGameSetupPolicies = 0x00698b1a;
const unsigned int kAddrDefaultGameSetupPoliciesEnd = 0x00698b52;
} // namespace

namespace {
const unsigned int kAddrClassDescTViewMgr = 0x0066f0b8;
const unsigned int kAddrTurnStateSeedLo = 0x006a5b58;
const unsigned int kAddrTurnStateSeedHi = 0x006a5b5c;
} // namespace

HCURSOR LoadTurnEventCursorByResourceIdOffset1000(int cursorResourceId);

// The RTTI/CRuntimeClass oracle previously assigned TViewMgr::CreateObject to
// 0x005d4c60, but that address's real body (verified via `just ghidra-listing`
// and `just ghidra-decompile`) is a CString truncate-with-ellipsis text helper --
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
  this->turnStateSeedLo = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedLo);
  this->turnStateSeedHi = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedHi);
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
    this->cursorTable[i] = LoadTurnEventCursorByResourceIdOffset1000(i + 1000);
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
  this->turnStateSeedLo = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedLo);
  this->turnStateSeedHi = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedHi);
  this->field10 = 0;
  this->mapUberPictureF0 = 0;
}

// FUNCTION: IMPERIALISM 0x005d5250
void TViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x005d5270
int TViewMgr::MapTurnEventCodeToPaletteIndex(int eventCode) {
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

// FUNCTION: IMPERIALISM 0x005d5750
void TViewMgr::ApplyTurnEventPaletteColorByEventCode(int eventCode) {
  int paletteIndex = this->MapTurnEventCodeToPaletteIndex(eventCode);
  SetQuickDrawFillColorFromPaletteIndex(static_cast<unsigned short>(paletteIndex));
}

// FUNCTION: IMPERIALISM 0x005d5780
void TViewMgr::UpdatePaletteIndexFromTurnEventCode(int eventCode) {
  int paletteIndex = this->MapTurnEventCodeToPaletteIndex(eventCode);
  UpdatePaletteIndexWithDefaultFallback(paletteIndex);
}

// FUNCTION: IMPERIALISM 0x005d57b0
void TViewMgr::HandleTurnEventVtableSlot40RefreshGoldDialog() {
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x7e5));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x223);
  }
  node->ShowTurnEventDialog(1);
  if (node->ResolveControlByTag(0x444c4f47) == nullptr) { // 'GOLD'
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x227);
  }
  void* content = node->QueryTurnEventContentObject();
  if (content != nullptr) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(content) + 0x14) = 0x70696335; // 'cip5'
  }

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);

  GoldDialogControl* gold = static_cast<GoldDialogControl*>(node->ResolveControlByTag(0x444c4f47));
  gold->AssertValid();
  gold->SetGoldControlStateByResource(0x24cd, 0);

  // Mask the game-flow flag while committing the refresh when localization mode is active.
  unsigned char savedFlag = 0;
  bool multiplayerActive = g_pSimMgr->multiplayerSessionRole != 0;
  if (multiplayerActive) {
    savedFlag = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
  }
  node->RefreshTurnEventDialog();
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
void TViewMgr::RunControlStringProviderAndDispatchLocalizedMessage(CString message,
                                                                   CString* messageStoreRef) {
  int overlayMode = this->ClassifyTurnStateForOverlayMode();
  this->DispatchLocalizedUiMessageWithTemplateA13A0(message, messageStoreRef, overlayMode, 0);
}

// FUNCTION: IMPERIALISM 0x005d5b00
undefined1 TViewMgr::DispatchLocalizedUiMessageWithTemplateA13A0(CString message,
                                                                 CString* messageStoreRef,
                                                                 int overlayMode, int arg4) {
  return this->DispatchLocalizedUiMessageWithTemplate(3, CString(g_szEmptyString), message,
                                                      messageStoreRef, overlayMode, arg4);
}

// FUNCTION: IMPERIALISM 0x005d5c40
undefined1 TViewMgr::DispatchLocalizedUiMessageWithTemplate(int templateKind, CString formatText,
                                                            CString message,
                                                            CString* messageStoreRef,
                                                            int overlayMode, int arg4) {
  // TODO: real body — builds and shows the localized message window.
  (void)templateKind;
  (void)formatText;
  (void)message;
  (void)messageStoreRef;
  (void)overlayMode;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005d5d30
bool TViewMgr::RunNationInfoModalAndReturnNonCancel(int overlayMode, CString messageText,
                                                    const char* infoChars, int infoLength,
                                                    int* eventPayload, int contextTag,
                                                    char showCancel) {
  CString titleText;
  TUiTextStyleDescriptor styleDescriptor;
  RECT bounds;             // function-scope like the original (0x38): not overlapped with the
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
  if (*eventPayload == -1000) {
    *reinterpret_cast<short*>(&payloadResource) = *reinterpret_cast<short*>(eventPayload + 1);
  }
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);

  TurnEventDialogNode* dialog;
  if (static_cast<short>(payloadResource) == 0) {
    dialog = static_cast<TurnEventDialogNode*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x7e4));
  } else {
    g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0(0xb);
    dialog = static_cast<TurnEventDialogNode*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2508));
  }
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x2e9);
  }
  dialog->ShowTurnEventDialog(1);
  void* content = dialog->QueryTurnEventContentObject();
  if (content != 0) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(content) + 0x14) = 0x6f6b6179; // 'okay'
  }

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(dialog, &placement);
  dialog->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);

  GoldDialogControl* gold =
      static_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47)); // 'GOLD'
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
  gold->SetGoldControlStateByResource(goldResource, 0);

  GoldDialogControl* coat =
      static_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x636f6174)); // 'coat'
  coat->AssertValid();
  if (coat == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x301);
  }
  if (g_pSimMgr->GetActiveNationId() >= 0 && g_pSimMgr->GetActiveNationId() < 7) {
    coat->SetGoldControlStateByResource(g_pSimMgr->GetActiveNationId() + 0x251c, 0);
  } else {
    coat->SetEnabled(0, 0);
  }

  if (static_cast<short>(payloadResource) != 0) {
    GoldDialogControl* goldValue =
        static_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47)); // 'GOLD'
    goldValue->AssertValid();
    goldValue->SetGoldControlStateByResource(contextTag + 0x252a, 0);
    GoldDialogControl* award =
        static_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x72657761)); // 'awer'
    award->AssertValid();
    award->SetGoldControlStateByResource(payloadResource, 0);
  } else {
    TStaticText* title =
        static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7469746c)); // 'titl'
    title->AssertValid();
    if (title == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x31a);
    }
    title->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
    title->SetTextAlignmentAndMaybeRefresh(1, 0);
    BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &titleText, 0x2749, overlayMode, 0x2749,
                                          contextTagSx);
    titleText += '\r';
    titleText += '\r';
    titleText += messageText;
    title->SetTextAndMaybeRefresh(&titleText, 0);
  }

  TDeluxeText* info = static_cast<TDeluxeText*>(dialog->ResolveControlByTag(0x696e666f)); // 'info'
  info->AssertValid();
  info->SetTextEntryFromChars(infoChars, infoLength);
  info->ApplyTextStyleDescriptorAndMaybeRefresh(&styleDescriptor, 0);
  int measuredHeight = static_cast<short>(info->MeasureCurrentTextWidthInLayoutRect());
  if (measuredHeight > info->frameHeight38) {
    info->QueryBounds(&bounds);
    bounds.right = bounds.top - 10;
    info->ApplyBounds(&bounds, 0);
    if (measuredHeight > info->frameHeight38) {
      TScrollView* scrollView = new TScrollView();
      scrollView->ConstructTScrollViewBaseState(gold, &info->ownerLocalX, &info->frameWidth34);
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
    TView* cancel = dialog->ResolveControlByTag(0x636e636c); // 'cncl'
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
    g_pSfxPlaybackSystem->PlaySoundEffect(overlaySfxIds[overlayMode], 0, 1);
  }

  int modalResult = dialog->RefreshTurnEventDialog();
  dialog->Close();
  dialog->Free();
  simSuppressed = g_pSimMgr->multiplayerSessionRole != 0;
  if (simSuppressed) {
    g_pGameFlowState->processPrimaryEventQueue = savedProcessFlag;
  }
  if (modalResult == 0x636e636c) { // 'cncl'
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

  int modalPayload[2];
  modalPayload[1] = resourceId;
  modalPayload[0] = -1000;
  RunNationInfoModalAndReturnNonCancel(overlayMode, CString(g_pNationInfoEmptyText_0066f050),
                                       static_cast<LPCSTR>(messageText), messageText.GetLength(),
                                       modalPayload, dialogContext, 0);
}

// FUNCTION: IMPERIALISM 0x005d69b0
void TViewMgr::ComputeTurnEventDialogPlacementByCode(TView* dialogView, POINT* outPlacement) {
  RECT mainBounds;
  g_pDisplayMgr->activeDialog->QueryBounds(&mainBounds);
  (void)mainBounds; // original makes the call but discards the result

  CIncludeView* mainView = GetMainViewHostFromActiveThread();
  RECT clientRect;
  GetClientRect(mainView->m_hWnd, &clientRect);

  RECT dialogBounds;
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
  if (code == 0x3b8 || code == 0x7dd) {
    designWidth = 0x200;
    designHeight = 0x1c0;
    margin = 0x16;
  } else if ((code >= 0x7d8 && code <= 0x7db) || code == 0x7de || code == 0x898 || code == 0xf3c ||
             code == 0xed8 || code == 0x2134 || code == 0x2260) {
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
  if (this->currentTurnEventCode == 0x7dd) {
    control = static_cast<TControl*>(mainView->ResolveControlByTag(0x74627231));
  } else {
    control = static_cast<TControl*>(mainView->ResolveControlByTag(0x746f6f6c));
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
void TViewMgr::UiRuntimeSlot58() {
  static const char kStatusIconTagBytes[] =
      " 0sr 1sr 2sr 3sr 4sr 5sr 6sr 0am 1am 2am 3am 4am 5am 0dg 1dg 2dg 3dg";
  TView* mainView = g_pDisplayMgr->activeDialog;
  const short nationId = this->pad06;
  for (short iconIndex = 0; iconIndex < 0x12; ++iconIndex) {
    const unsigned int tag =
        *reinterpret_cast<const unsigned int*>(kStatusIconTagBytes + iconIndex * 4);
    TControl* control = static_cast<TControl*>(mainView->ResolveControlByTag(tag));
    if (control != nullptr) {
      control->AssertValid();
      g_pStrategicMapViewSystem->OrphanCallChain_C4_I35_0050bbc0(reinterpret_cast<int*>(control),
                                                                 iconIndex, nationId);
    }
  }
  TGreatPower* nation = g_apNationStates[nationId];
  if (nation != nullptr) {
    nation->SnapshotDiplomacyState1c6Into250();
  }
}

// FUNCTION: IMPERIALISM 0x005d6cd0
void TViewMgr::HandleTurnEventDialogFactorySlot70(int eventCode) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(eventCode, 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x4ff);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->Open();
}

// FUNCTION: IMPERIALISM 0x005d6d70
void TViewMgr::HandleTurnEventDialogFactorySlot74(int eventCode) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(eventCode, 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x514);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6e30
void TViewMgr::UiRuntimeSlot8C(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x005d6e50
void TViewMgr::HandleTurnEventDialogFactorySlot78(int eventCode) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(eventCode, 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x535);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6f10
void TViewMgr::HandleTurnEventDialogFactorySlot7C(int eventCode) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(eventCode, 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x54e);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d6fd0
void TViewMgr::HandleTurnEventDialogFactorySlot80(int eventCode) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(eventCode, 0));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0x566);
  }
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  if (gold != nullptr) {
    gold->CommitGoldDialogContent();
  }
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005d7090
char TViewMgr::RequestDiplomacyDecisionSlot90(int sourceNation, int targetNation,
                                              int proposalCode) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  DispatchTurnEventSlot4C(0x7d8, sourceNation);
  TDiplomacyMapView* mainView =
      static_cast<TDiplomacyMapView*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainView->AssertValid();
  mainView->InvalidateAndForwardTabSwitchToChild(reinterpret_cast<void*>(sourceNation),
                                                 reinterpret_cast<void*>(targetNation),
                                                 reinterpret_cast<void*>(proposalCode));
  return 0;
}

// FUNCTION: IMPERIALISM 0x005d7100
char TViewMgr::RequestDecisionSlot94(int sourceNation, int arg1, int arg2, int promptCode) {
  if (IsTurnCooldownCounterActiveOrResetFlag()) {
    return 1;
  }
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  DispatchTurnEventSlot4C(0x7d8, sourceNation);
  TDiplomacyMapView* mainView =
      static_cast<TDiplomacyMapView*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainView->AssertValid();
  mainView->InvalidateAndRunChildWaitSheet(
      reinterpret_cast<void*>(sourceNation), reinterpret_cast<void*>(arg1),
      reinterpret_cast<void*>(arg2), reinterpret_cast<void*>(promptCode));
  // The original's non-cooldown path leaves AL from the (void) child call; the trailing
  // xor al,al this emits is the sole residual diff (InvalidateAndRunChildWaitSheet is void,
  // so its incidental AL cannot be tail-returned without regressing 0x4f7040's own match).
  return 0;
}

// FUNCTION: IMPERIALISM 0x005d7190
void TViewMgr::UiRuntimeSlotD4(int arg) {
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

void RefreshMainCouncilTickerPanel() {
  TControl* mainPanel = ResolveMainTaggedControl(kControlTagMain);
  if (mainPanel != nullptr) {
    mainPanel->AssertValid();
    TCouncilView* councilPanel = static_cast<TCouncilView*>(static_cast<void*>(mainPanel));
    councilPanel->InitializeDiplomacyCouncilViewControlsAndTicker();
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
  TToolBarCluster* tradCluster = static_cast<TToolBarCluster*>(tradControl);
  const short pictureId = static_cast<short>(tradCluster->selectedChildTag + 1);
  static_cast<TPicture*>(tradControl)->SetPictureResourceIdAndRefresh(pictureId, false);
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
  TUiTextStyleDescriptor styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, styleWidth, styleSecondary);
  control->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
  (void)stylePrimary;
}

void RefreshQuerControlLayoutAndClearText() {
  TControl* querControl = ResolveMainTaggedControl(kControlTagQuer);
  if (querControl == nullptr) {
    return;
  }
  querControl->AssertValid();
  int layoutCaptureBuffer = 0;
  querControl->CaptureLayoutF0(&layoutCaptureBuffer, 0);
  querControl->SetHoverHelpText(g_szEmptyString);
}

} // namespace turn_event_ui_refresh

namespace {
void DispatchPostTurnStateUpdatesTail() {
  if (g_pHelpMgr == nullptr) {
    return;
  }
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  g_pHelpMgr->HandlePostDispatchTurnStateEventUpdates();
  g_pHelpMgr->HandlePendingEventActivationByCode(g_pUiRuntimeContext->currentTurnEventCode);
  g_pHelpMgr->HandlePostPendingEventActivationNoOp(g_pUiRuntimeContext->currentTurnEventCode);
}
} // namespace

// FUNCTION: IMPERIALISM 0x005d71b0
void TViewMgr::DispatchDecisionSlot98(int sourceNation, int arg1, int arg2, int arg3,
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
  mainControl->InvokeMainAction(reinterpret_cast<void*>(sourceNation),
                                reinterpret_cast<void*>(arg1), reinterpret_cast<void*>(arg2),
                                reinterpret_cast<void*>(arg3),
                                reinterpret_cast<void*>(targetNation));
}

// FUNCTION: IMPERIALISM 0x005d7240
void TViewMgr::DispatchTurnEventSlot4C(short eventCode, int payload) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  const short newCode = eventCode;
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
    if (curCode == 0x2134) {
      ModifyMainViewChildWindowStyleClear02000000(mainView);
    } else {
      switch (curCode) {
      case 0x7d9:
      case 0x7da:
        this->UiRuntimeSlot58();
        break;
      case 0x7db:
        g_pStrategicMapViewSystem->OrphanCallChain_C1_I10_0050d920();
        break;
      case 0x7dd:
        this->mapUberPictureF0 = 0;
        break;
      }
    }
  }

  // Code 0 = rebuild every registered UI window node.
  if (newCode == 0) {
    static_cast<TAmbitApplication*>(g_pGlobalUiRootController)->dispatchBusyFlag4c = 0;
    this->currentTurnEventCode = 0;
    g_pDisplayMgr->clipSnapshotEvent = 0;
    mainView->Close();
    CWMgrIterator iter;
    iter.Reset(1);
    TWindow* window = static_cast<TWindow*>(iter.FirstWindow());
    while (iter.More() != 0) {
      const unsigned int tag = static_cast<unsigned int>(window->controlTag);
      if (tag == kControlTagWpam || tag == kControlTagWnrt) {
        window->CloseAndFree();
      }
      window = static_cast<TWindow*>(iter.NextWindow());
    }
    return;
  }

  // Same-code refresh: refresh the main view, then run the per-code hook.
  if (newCode == this->currentTurnEventCode) {
    if (secondary != -1) {
      this->pad06 = secondary;
    }
    if (newCode == 0x5e4) {
      QueueDeferredUiEventPacket(mainView, 0x29a, mainView);
    } else if (newCode == 0x547) {
      mainView->RefreshControl();
      g_pCursorControlPanel->AssertValid();
    } else if (newCode == 0x8fc) {
      mainView->RefreshControl();
      HandleTurnEvent8FC_RebuildPageTabsAndTitles();
    } else if (newCode == 0x7d8) {
      if (static_cast<short>(g_pSimMgr->mode) == 0x68) {
        mainView->RefreshControl();
        this->UiRuntimeSlot6C(newCode);
      }
    } else if (newCode == 0x7d9 || newCode == 0x7da) {
      mainView->RefreshControl();
      this->UiRuntimeSlot5C(newCode);
    } else if (newCode == 0x7db) {
      mainView->RefreshControl();
      this->UiRuntimeSlotA8(newCode);
    } else if (newCode == 0x7dd) {
      mainView->RefreshControl();
      this->HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(newCode);
    } else if (newCode == 0x7de) {
      mainView->RefreshControl();
      this->UiRuntimeSlot84(newCode);
    } else if (newCode == 0x2103) {
      this->UiRuntimeSlot9C();
    } else if (newCode == 0x2260) {
      mainView->RefreshControl();
      this->HandleTurnEvent2260_RefreshMainHudTitles(newCode);
    }
    DispatchPostTurnStateUpdatesTail();
    return;
  }

  // Cross-code path: tear down the previous dialog, build the new turn-event UI packet.
  g_pUiViewManager->NoOpRuntimeUiCallback_005df780(0);
  mainView->Open();
  if (this->field10 != 0) {
    ShowDialogTemplateE0ModalAndReleaseCapture();
    this->field10 = 0;
  }
  TControl* inclControl =
      static_cast<TControl*>(mainView->ResolveControlByTag(0x496e636c)); // 'Incl'
  if (inclControl != nullptr) {
    inclControl->AssertValid();
    inclControl->RefreshControl();
    inclControl->Free();
  }

  TIncludeView* packet = ::new TIncludeView();
  CString emptyText(g_szEmptyString);
  int anchorPoint[2] = {0, 0};
  packet->BuildTurnEventFactoryPacket(nullptr, mainView, newCode, anchorPoint, &emptyText, 1);
  packet->DoPostCreate(0);
  packet->controlTag = 0x496e636c; // 'Incl'
  packet->RefreshControl();
  g_pDisplayMgr->LoadMainViewClipSnapshotIntoQuickDrawState(static_cast<unsigned short>(newCode));
  if (this->field10 != 0) {
    ShowDialogTemplateE0ModalAndReleaseCapture();
    this->field10 = 0;
  }
  this->currentTurnEventCode = newCode;

  if (newCode > 0x3c0) {
    if (newCode < 0x5dd) {
      if (newCode == 0x5dc) {
        this->UiRuntimeSlotF8();
      } else if (newCode == 0x547) {
        this->UiRuntimeSlot50(static_cast<int>(newCode));
      }
    } else if (newCode < 0x7d9) {
      switch (newCode) {
      case 0x5dd:
        this->NoOpTurnEventStateVtableSlotFC();
        break;
      case 0x5de:
        this->HandleTurnEvent5DE_RefreshMainView();
        break;
      case 0x5df:
        this->HandleTurnEvent5DF_RefreshMainView();
        break;
      case 0x5e0:
        this->UiRuntimeSlot108();
        break;
      case 0x7d8:
        this->UiRuntimeSlot6C(newCode);
        break;
      }
    } else if (newCode > 0x898) {
      if (newCode == 0xed8 || newCode == 0xf3c) {
        this->UiRuntimeSlotA0();
      } else if (newCode == 0x8fc) {
        HandleTurnEvent8FC_RebuildPageTabsAndTitles();
      } else if (newCode == 0x11f8) {
        this->HandleTurnEventDialogFactorySlotF4();
      } else if (newCode == 0xf3d) {
        this->HandleTurnEventF3D_PopulateRecentTurnMessages(static_cast<int>(secondary));
      } else if (newCode == 0x2103) {
        this->HandleTurnEvent2260_RefreshMainHudTitles(newCode);
      } else if (newCode == 0x2134) {
        this->HandleTurnEventVtableSlot60ActivateMainDialog(newCode);
      } else if (newCode == 0x2260) {
        this->UiRuntimeSlot9C();
      }
    } else if (newCode == 0x898) {
      this->HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(newCode);
    } else {
      switch (newCode) {
      case 0x7d9:
        this->HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(newCode);
        break;
      case 0x7da:
        this->UiRuntimeSlot5C(newCode);
        break;
      case 0x7db:
        this->UiRuntimeSlotA8(newCode);
        break;
      case 0x7dd:
        this->UiRuntimeSlot50(static_cast<int>(secondary));
        break;
      case 0x7de:
        this->UiRuntimeSlot84(newCode);
        break;
      case 0x7e0:
        this->UiRuntimeSlot50(static_cast<int>(secondary));
        break;
      }
    }
  } else if (newCode == 0x3c0) {
    this->HandleTurnEventTable66F220_Slot0C_InvokeGoldViewSlots0C_1E4_14x14();
  } else if (newCode == 0x3b8) {
    this->UiRuntimeSlotD0(newCode);
  }
  DispatchPostTurnStateUpdatesTail();
}

// FUNCTION: IMPERIALISM 0x005d7c40
void TViewMgr::UiRuntimeSlotA4(int payload, TEventHandler* waitTarget) {
  DispatchTurnEventSlot4C(0x3b8, payload);
  while (static_cast<short>(waitTarget->field14) == 0) {
    if (PumpUiMessagesAndBackgroundTasks(1) == 0) {
      PostWmCloseToMainThreadWindow();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005d7cb0
void TViewMgr::UiRuntimeSlotA8(int) {
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

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagQuer));
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->SetHoverHelpText(g_szEmptyString);
  }
}

// FUNCTION: IMPERIALISM 0x005d7f70
void TViewMgr::InvokeStrategicMapViewMethod5C() {
  g_pStrategicMapViewSystem->OrphanLeaf_NoCall_Ins06_0050d8d0();
}

// FUNCTION: IMPERIALISM 0x005d7f90
void TViewMgr::InvokeStrategicMapViewMethod60(short param1) {
  g_pStrategicMapViewSystem->OrphanLeaf_NoCall_Ins06_0050d8f0(param1);
}

// FUNCTION: IMPERIALISM 0x005d7fc0
void TViewMgr::UiRuntimeSlot50(int payload) {
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
void TViewMgr::UiRuntimeSlot6C(int) {
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

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
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
void TViewMgr::UiRuntimeSlot84(int) {
  turn_event_ui_refresh::RefreshMainCouncilTickerPanel();
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();

  TControl* tranControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTran);
  if (tranControl != nullptr) {
    tranControl->AssertValid();
    tranControl->SetState(0, 0);
    tranControl->SwitchActiveChildAndNotify(nullptr);
    tranControl->SetHoverHelpText(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagQuer);
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->SetHoverHelpText(g_szEmptyString);
  }
}

// FUNCTION: IMPERIALISM 0x005d8980
void TViewMgr::UiRuntimeSlot88(int abilityIndex) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TUiTextStyleDescriptor style;
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
  textControl->SetTextStyleAndMaybeRefresh(&style, 0);
  textControl->SetTextAlignmentAndMaybeRefresh(-2, 0);
  activeDialog->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x005d8c40
void TViewMgr::UiRuntimeSlot9C(int pageIndex) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  TNewspaperView* mainControl =
      static_cast<TNewspaperView*>(activeDialog->ResolveControlByTag(kControlTagMain));
  mainControl->AssertValid();
  g_pSfxPlaybackSystem->PlaySoundEffect(0x14b4, 0, 1);
  mainControl->BuildInterNationEventSummaryRowsForAdvisorDialog(pageIndex);
  activeDialog->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x005d8cc0
void TViewMgr::UiRuntimeSlotA0() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CTemporaryRegion temporaryRegion;
  TTacticalBattleView* goldControl =
      static_cast<TTacticalBattleView*>(activeDialog->ResolveControlByTag(kControlTagGold));
  goldControl->AssertValid();
  goldControl->SyncStatusPanelBounds();

  turn_event_dialog::GoldSinglePayloadControl* owner =
      static_cast<turn_event_dialog::GoldSinglePayloadControl*>(goldControl->ownerContext);
  owner->AssertValid();

  RECT bounds;
  goldControl->QueryBounds(&bounds);
  RECT regionBounds = bounds;
  RectRgn(temporaryRegion.tempRgn, &regionBounds);

  owner->ApplyPayload(temporaryRegion.tempRgn);
}

// FUNCTION: IMPERIALISM 0x005d8dd0
void TViewMgr::UiRuntimeSlot5C(int) {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  turn_event_ui_refresh::RefreshTradClusterPictureAndHintText();
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagBpot, 0x2730, 0);

  TControl* textControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagText);
  if (textControl != nullptr) {
    textControl->AssertValid();
    textControl->SetHoverHelpText(g_szEmptyString);
  }

  const short activeNationId = g_pSimMgr->GetActiveNationId();
  g_apNationStates[activeNationId]->ReturnFalseNationStateCapabilityFlag9C();
  this->fieldEc = 0;
  for (short metricSlot = 0; metricSlot < 0x11; ++metricSlot) {
    if (g_apNationStates[activeNationId]->QueryNationMetricBySlot7C(metricSlot) == -1) {
      this->fieldEc = static_cast<short>(this->fieldEc + 1);
    }
  }

  turn_event_ui_refresh::ApplyThemeToTaggedTextControl(kControlTagText, 0xc, 0x2b67, 0x2b6c);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagText, 0x2730, 0);
  turn_event_ui_refresh::ApplyThemeToTaggedTextControl(kControlTagFood, 0xc, 0x2b67, 0x2b6c);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2731, 0);

  TUiTextStyleDescriptor foodStyle;
  foodStyle.fontFamily = 0;
  foodStyle.fontStyleFlags = 0;
  foodStyle.fontSize = 0;
  foodStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&foodStyle, 0, 0xc, 0x2b6b);
  TControl* foodControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagFood);
  if (foodControl != nullptr) {
    foodControl->AssertValid();
    foodControl->SetTextStyleAndMaybeRefresh(&foodStyle, 0);
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
    foodControl->SetTextStyleAndMaybeRefresh(&foodStyle, 0);
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
    foodControl->SetTextStyleAndMaybeRefresh(&foodStyle, 0);
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
  }

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagQuer, 0x2730, 0);

  UiRuntimeSlot58();
}

// FUNCTION: IMPERIALISM 0x005da040
void TViewMgr::HandleTurnEventVtableSlot60ActivateMainDialog(int) {
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
      static_cast<TControl*>(mainControl->ResolveControlByTag(0x7469744c)); // 'titL'
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
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTrb1);
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
  TMovieView* movieView = static_cast<TMovieView*>(activeDialog->ResolveControlByTag(0x6d6f7669));
  movieView->AssertValid();
  movieView->SetState(1, 0);
  movieView->InvokeSlot13C();

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
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
    return;
  case 0xe:
  case 0x16:
  case 0x17:
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x7e0);
    return;
  case 0x19:
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(g_pSimMgr->GetActiveNationId())) {
      g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5eb);
      return;
    }
  default:
    ReinitializeGameFlowAndPostTurnEventCode(0);
  }
}

// Main-menu screen setup (turn-event 0x5dc): resets the background-music cue pools, then
// configures the 'curs' cursor-info panel's style/theme and finally sets every menu button's
// localized label (the 'main' council-ticker slot is cleared instead of labeled).
// FUNCTION: IMPERIALISM 0x005db780
void TViewMgr::UiRuntimeSlotF8() {
  TView* mainView = g_pDisplayMgr->activeDialog;

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(6);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();

  g_pCursorControlPanel = nullptr;
  g_pCursorControlPanel =
      static_cast<TInfoBarText*>(mainView->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();

  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);

  TUiTextStyleDescriptor styleDescriptor = {0, 0, 0, 0};
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xe, 0x2b6c);
  g_pCursorControlPanel->ApplyTextStyleDescriptorAndMaybeRefresh(&styleDescriptor, 1);
  g_pCursorControlPanel->SetTextAlignmentAndMaybeRefresh(1, 0);

  int mappedStyleFlags = 0;
  MapUiThemeCodeToStyleFlags(0x2b6b, &mappedStyleFlags);
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
void TViewMgr::UiRuntimeSlot108() {
  TView* mainPanel = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
  mainPanel->AssertValid();
  mainPanel->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005dc160
void TViewMgr::InvokeStrategicMapViewMethod6C() {
  g_pStrategicMapViewSystem->MacViewMgrSlot1B();
}

// FUNCTION: IMPERIALISM 0x005dc180
undefined TViewMgr::InvokeStrategicMapViewMethod68() {
  return g_pStrategicMapViewSystem->RenderOffscreenBitmapGridStripAndRestoreContext();
}

// FUNCTION: IMPERIALISM 0x005dc1a0
undefined TViewMgr::InvokeStrategicMapViewMethod74() {
  return g_pStrategicMapViewSystem->RebuildMapTileNeighborHighlightPolygonsForAllTiles();
}

// FUNCTION: IMPERIALISM 0x005dc1c0
undefined TViewMgr::InvokeStrategicMapViewMethod70() {
  return g_pStrategicMapViewSystem->RenderTurnEventPalettePreviewSurfaceAndProgress();
}

// FUNCTION: IMPERIALISM 0x005dc1e0
void TViewMgr::UiRuntimeSlotD0(int) {
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* goldControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagGold);
  if (goldControl != nullptr) {
    goldControl->AssertValid();
    goldControl->RefreshControl();
  }

  turn_event_ui_refresh::RefreshMainCouncilTickerPanel();
}

// FUNCTION: IMPERIALISM 0x005dc3f0
void TViewMgr::HandleTurnEventTable66F220_Slot0C_InvokeGoldViewSlots0C_1E4_14x14() {
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  gold->ConfigureGoldValueCells(0x14, 0x14);
}

// FUNCTION: IMPERIALISM 0x005dc430
void TViewMgr::HandleTurnEventDialogFactorySlotB8(int a, int b, int c) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2405));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0xf50);
  }
  node->ShowTurnEventDialog(1);
  GoldCommitControl* gold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->AssertValid();
  if (gold == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0xf54);
  }
  gold->ApplyGoldTradeSummaryValues(a, b, c);
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  int refreshResult = node->RefreshTurnEventDialog();
  gold->ApplyGoldTradeDialogRefreshResult(refreshResult);
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dc690
void TViewMgr::HandleTurnEventF3D_PopulateRecentTurnMessages(int nationSlot) {
  (void)nationSlot;
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

// FUNCTION: IMPERIALISM 0x005dcdf0
char TViewMgr::UiRuntimeSlotB4(void* payload) {
  turn_event_dialog::ThreeFlagDialogNode* node =
      static_cast<turn_event_dialog::ThreeFlagDialogNode*>(
          g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x3b9));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xbe);
  }
  turn_event_dialog::GoldSinglePayloadControl* gold =
      static_cast<turn_event_dialog::GoldSinglePayloadControl*>(
          node->ResolveControlByTag(kControlTagGold));
  if (gold == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xc0);
  }
  gold->ApplyPayload(payload);
  node->ConfigureDialogFlags(1, 1, 1);
  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->ShowTurnEventDialog(1);
  int result = node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
  return result == static_cast<int>(kControlTagCncl) ? static_cast<char>(0) : static_cast<char>(1);
}

// FUNCTION: IMPERIALISM 0x005dcf20
void TViewMgr::HandleTurnEventDialogFactorySlotD8(int) {
  GoldCommitControl* rootGold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagGold)));
  if (rootGold == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xe2);
  }
  rootGold->NotifyGoldControlOfTurnEventCode(currentTurnEventCode);

  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x546));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xe5);
  }
  GoldFactoryPanel* gold = static_cast<GoldFactoryPanel*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagGold)));
  if (gold == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xe6);
  }
  gold->NotifyDialogOwner(this);

  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd0a0
int TViewMgr::ShowConstructionOptionsDialog(int dialogValue) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x1c20));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x100);
  }
  turn_event_dialog::GoldDialogValueControl* gold =
      static_cast<turn_event_dialog::GoldDialogValueControl*>(
          node->ResolveControlByTag(kControlTagGold));
  gold->ApplyDialogValue(reinterpret_cast<void*>(dialogValue));
  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->ShowTurnEventDialog(1);
  int result = node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
  return result;
}

// FUNCTION: IMPERIALISM 0x005dd180
void TViewMgr::UiRuntimeSlotE0(int nationSlot, int unused) {
  (void)unused;
  if (static_cast<short>(nationSlot) == g_pGlobalMapState->pendingRiverMouthTile22) {
    TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x24f9));
    if (node == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x11e);
    }
    node->RefreshTurnEventDialog();
    node->Close();
    node->Free();
    return;
  }
  g_pHelpMgr->EnsureMapActionContextViewAndBuildDefaultTileMenu(nationSlot);
}

// FUNCTION: IMPERIALISM 0x005dd220
void TViewMgr::HandleTurnEventDialogFactorySlotE4(int stringCode) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x1c52));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x14a);
  }
  TControl* gold = static_cast<TControl*>(node->ResolveControlByTag(0x444c4f47)); // 'GOLD'
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->RefreshTurnEventDialog();
  TDeluxeText* nameText =
      static_cast<TDeluxeText*>(static_cast<TView*>(gold->ResolveControlByTag(0x6e616d65)));
  if (nameText == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x156);
  }
  nameText->SetTextFromUiStringResourceId(static_cast<short>(stringCode));
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd340
void TViewMgr::HandleTurnEventDialogFactorySlotF0(TTaskForce* activeMapOrderEntry) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2506));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x167);
  }
  TView* page = node->ResolveControlByTag(0x70616765); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x169);
  }
  // Ground truth (byte 0x1b8) rebuilds 'page's roster around activeMapOrderEntry, but the
  // concrete roster subclass installed as 'page' here isn't recovered yet (same gap as
  // HandleTurnEventDialogFactorySlotEC above) -- left undone rather than fake the cast
  // (Hard Rule 12).
  (void)page;
  (void)activeMapOrderEntry;

  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd770
void TViewMgr::UiRuntimeSlotE8(void* selection) {
  // Only the +2 city-record index is established for this opaque event payload.
  struct TurnEventMapSelection {
    short unresolved0;
    short cityRecordIndex2;
  };
  TurnEventMapSelection* mapSelection = static_cast<TurnEventMapSelection*>(selection);

  GoldCommitControl* activeGold = static_cast<GoldCommitControl*>(
      g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagGold));
  if (activeGold == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1c5);
  }
  short cityRecordIndex = mapSelection->cityRecordIndex2;
  activeGold->NotifyGoldControlOfTurnEventCode(
      g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex04);

  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xf0a));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1c9);
  }
  turn_event_dialog::GoldDialogValueControl* gold =
      static_cast<turn_event_dialog::GoldDialogValueControl*>(
          node->ResolveControlByTag(kControlTagGold));
  if (gold == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1ca);
  }
  gold->ApplyDialogValue(selection);
  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd900
void TViewMgr::HandleTurnEventDialogFactorySlotEC(int mapSelection) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xdac));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1e2);
  }
  TView* page = node->ResolveControlByTag(0x70616765); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1e3);
  }
  // Mac identity plus the Windows +0x8c tile-index store recover the concrete page as
  // TGarrisonView. StuffValues rebuilds its TArmyUnitLine roster for this map tile.
  static_cast<TGarrisonView*>(page)->StuffValues(static_cast<short>(mapSelection));

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();

  // Ground truth then dispatches
  // mapUberPictureF0->categoryPages[activeUnitCategoryIndex96]'s own slot-0x74 virtual with
  // mapSelection (matching the arity fixed on TMapUberUberPicture::AutoScrollByEdgeMask),
  // but categoryPages' concrete element class isn't recovered yet -- left undone (Hard Rule
  // 12) rather than fake that dispatch too.
  (void)mapSelection;
}

// FUNCTION: IMPERIALISM 0x005ddd20
void TViewMgr::ShowCivilianLedgerDialogAndSelectUnit() {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xdac));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x232);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(0x70616765)); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x233);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperCivRoster* roster = ::new TSuperCivRoster();
  int rosterBounds[4] = {0x1ca, 0x136, 0xd, 0x2e};
  TView* runningDialog = roster;
  roster->InitializeLedgerRosterPages(pageOwner, rosterBounds, &runningDialog);
  roster->controlTag = 0x70616765; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->InitializeTextEntryBaseAndOptionalStringResource(
      static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746, 0xa);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->ShowTurnEventDialog(1);
  node->RefreshTurnEventDialog();
  short selectedIndex = roster->selectedIndex84;
  node->Close();
  node->Free();

  if (selectedIndex != -1) {
    this->mapUberPictureF0->NotifySubviewOfSelectedTile(selectedIndex);
    int orderState =
        g_pGlobalMapState->terrainStateTable[selectedIndex].firstCivilianOrder20->field_8;
    if (orderState == 0 || orderState == 3 || orderState == 2) {
      g_pSelectedCivilianOrderState->HandleCivilianTileSelectionOrReportClick(selectedIndex, 2);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005de010
int TViewMgr::MakePlanetSeedDialog(const char* instruction, CString& planetSeed,
                                   const char* firstChoice, const char* secondChoice,
                                   int initialChoice, unsigned char showCancel) const {
  TWindow* dialog =
      static_cast<TWindow*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x3ba));
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x26a);
  }

  dialog->SetModality(1);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay;
  }

  TStaticText* instructionText =
      static_cast<TStaticText*>(dialog->ResolveControlByTag(0x696e7374 /* 'inst' */));
  instructionText->AssertValid();
  TUiTextStyleDescriptor instructionStyle;
  instructionStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&instructionStyle, 0, 0xe, 0);
  instructionText->SetTextStyleAndMaybeRefresh(&instructionStyle, 0);
  CString instructionString(instruction);
  instructionText->SetTextAndMaybeRefresh(&instructionString, 0);

  TEditText* planetEdit =
      static_cast<TEditText*>(dialog->ResolveControlByTag(0x706c616e /* 'plan' */));
  planetEdit->AssertValid();
  CString editText(planetSeed);
  TUiTextStyleDescriptor editStyle;
  editStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&editStyle, 0, 0xc, 0);
  planetEdit->SetTextStyleAndMaybeRefresh(&editStyle, 0);
  planetEdit->InitDialogWindowAndSyncTitleIfChanged(&editText, 0);
  planetEdit->ActivateCityProductionViewIfAllowed();
  planetEdit->SetEditSelectionAndScrollCaret(0, static_cast<short>(editText.GetLength()), 1);
  dialog->SetWindowTarget(planetEdit);

  int mappedTheme = 0;
  MapUiThemeCodeToStyleFlags(0x2b6c, &mappedTheme);
  g_pDisplayMgr->SetMapTileIconVariantTriplet(reinterpret_cast<undefined1*>(&mappedTheme));
  UpdatePaletteIndexWithDefaultFallback(0x3b);

  TRadioTextCluster* choiceCluster =
      static_cast<TRadioTextCluster*>(dialog->ResolveControlByTag(0x316f7232 /* '1or2' */));
  choiceCluster->AssertValid();
  if (firstChoice != 0) {
    choiceCluster->SetEnabled(1, 0);
    choiceCluster->frameThemeCode90 = 0x2b6b;
    choiceCluster->itemInset92 = 2;

    TRadioText* first =
        static_cast<TRadioText*>(choiceCluster->ResolveControlByTag(0x6f6e6531 /* 'one1' */));
    first->AssertValid();
    CString firstText(firstChoice);
    first->SetTextAndMaybeRefresh(&firstText, 0);
    ApplyUiTextStyleAndThemeFlags(first, 0, 0xc, 0x2b6b, 0x2b6c);
    first->SetTextAlignmentAndMaybeRefresh(1, 0);

    TRadioText* second =
        static_cast<TRadioText*>(choiceCluster->ResolveControlByTag(0x74776f32 /* 'two2' */));
    second->AssertValid();
    CString secondText(secondChoice);
    second->SetTextAndMaybeRefresh(&secondText, 0);
    ApplyUiTextStyleAndThemeFlags(second, 0, 0xc, 0x2b6b, 0x2b6c);
    second->SetTextAlignmentAndMaybeRefresh(1, 0);

    choiceCluster->SetSelectedTextOptionByTag(
        initialChoice == 0 ? 0x6f6e6531 /* 'one1' */ : 0x74776f32 /* 'two2' */, false);
  }

  if (showCancel != 0) {
    TControl* cancel = static_cast<TControl*>(dialog->ResolveControlByTag(kControlTagCanc));
    cancel->AssertValid();
    cancel->SetEnabled(1, 0);
    cancel->SetState(1, 0);
  }

  int resultTag = dialog->PoseModally();
  if (firstChoice != 0) {
    resultTag = choiceCluster->selectedTag88;
  }

  planetEdit->GetCurrentText(&editText);
  planetSeed = editText;
  dialog->Close();
  dialog->Free();
  return resultTag;
}

// FUNCTION: IMPERIALISM 0x005de4f0
bool TViewMgr::ShowCivilianReportDialogAndReturnConfirm(TCivUnit* pCivilianOrderEntry) {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xbc4));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x2c1);
  }
  node->ShowTurnEventDialog(1);
  TCivilianReportGoldControl* gold = static_cast<TCivilianReportGoldControl*>(
      static_cast<TView*>(node->ResolveControlByTag(0x444c4f47))); // 'GOLD'
  gold->PopulateCivilianReportContent(pCivilianOrderEntry);
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  unsigned int resultTag = node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
  return resultTag == 0x6f6b6179;
}

// FUNCTION: IMPERIALISM 0x005de5d0
bool TViewMgr::DispatchProvinceOrderOverlayConfirmDialog(short cityRecordIndex,
                                                         int* categoryCounts) {
  // TODO: port body @ 0x5de5d0 (181 bytes). The dialog-node resolve/SetField84(1)/
  // ResolveControlByTag('DLOG') prefix mirrors MakePlanetSeedDialog (0x5de010), but the
  // 'DLOG' control's own slot-0x1cc dispatch (the actual message-formatting call that
  // forwards cityRecordIndex/categoryCounts) needs a class not yet recovered. Stubbed
  // to the conservative "not confirmed" default.
  (void)cityRecordIndex;
  (void)categoryCounts;
  return false;
}

// FUNCTION: IMPERIALISM 0x005de8f0
void TViewMgr::DispatchUiRuntimeMessage101AAndRefreshActiveView() {
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x101a));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x33f);
  }
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->RefreshTurnEventDialog();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005de990
char TViewMgr::ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex,
                                                    int overlayMode, int arg4) {
  CString message;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, uiStringGroup,
                                                                  uiStringIndex);
  return DispatchLocalizedUiMessageWithTemplateA13A0(message, &g_cstrUiPromptMessageStore,
                                                     overlayMode, arg4);
}

// FUNCTION: IMPERIALISM 0x005dea60
void TViewMgr::CreateModalMessageCommandAndQueue(CString* message, int payload) {
  TModalMessageCommand* command = new TModalMessageCommand();
  command->message = *message;
  command->payload = payload;
  command->InitializeRangePair(0x48657921 /* 'Hey!' */, g_pGlobalUiRootController, 0, 0, 0);
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005deb40
char TViewMgr::DispatchGameStateEventIfLocalizedPromptAccepted(int actionTag) {
  CString message;
  int sessionRole = g_pSimMgr->multiplayerSessionRole;
  unsigned char isClientSession = sessionRole == 2;
  if (isClientSession != 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x31);
  } else {
    unsigned char hosting = sessionRole == 1;
    if (hosting != 0) {
      if (actionTag == 0x6367616d) { // 'magc'
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x37);
      } else {
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2f);
      }
    } else if (actionTag == 0x6e657767) { // 'gwen'
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2b);
    } else if (actionTag == 0x71756974) { // 'quit'
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2a);
    } else if (actionTag == 0x6c6f6164) { // 'load'
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x33);
    } else {
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2b);
    }
  }
  char accepted = g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
      message, &g_cstrUiPromptMessageStore, 0, 1);
  if (accepted != 0) {
    unsigned char isClientSession = g_pSimMgr->multiplayerSessionRole == 2;
    if (isClientSession != 0) {
      g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x61626469, // 'abdi'
                                                         g_pSimMgr->GetActiveNationId(), -2);
    }
  }
  return accepted;
}
