#include <mbstring.h>
#include "game/TScopedWaitCursor.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_screens.h"
#include "game/net/TLoungeDialog.h"
#include "game/ui_core/TLanguageMgr.h"

#include "game/ui_screens/CString.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TApplication.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/net/TPoseMessageDialog.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0044fae0
// TLoungeDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0044fb60
TLoungeDialog::~TLoungeDialog() {}
// SYNTHETIC: IMPERIALISM 0x0054d650
// TLoungeDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054d6d0
// TLoungeDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLoungeDialog, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0054d6f0
void TLoungeDialog::Free() {
  if (g_nSaveFormatVersion != kControlTagMoil) { // 'Moil'
    g_pGameFlowState->EnableDiplomacyQueueRoutingAndSetContextField44(this, 0);
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x0054d730
void TLoungeDialog::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  g_pGameFlowState->EnableDiplomacyQueueRoutingAndSetContextField44(this, 1);

  // 'labl' is a TInfoBarText control (vtable slot 0x204 matches
  // TInfoBarText::InitializeMapHintTextStyleAndThemeFlags exactly). The original also
  // installs it as the shared cursor-hint panel.
  TInfoBarText* lablControl = static_cast<TInfoBarText*>(ResolveControlByTag(kSessionTagLabl));
  g_pCursorControlPanel = lablControl;
  lablControl->AssertValid();
  lablControl->SetTextStyle(0, 0xe, 0x2b6b);
  lablControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  lablControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  // Per-nation-slot roster rows: a ready-state radio ('rad0'-'rad6'), a portrait/pick
  // button ('pik0'-'pik6'), and a name label ('nam0'-'nam6'), each initialized with a
  // blank caption via the same restyle idiom as RefreshMapAndMessageControlsForCurrentContext.
  for (int i = 0; i < 7; ++i) {
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 6,
                                                          kSessionTagRad0 + i); // 'rad0'-'rad6'
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 7,
                                                          kSessionTagPik0 + i); // 'pik0'-'pik6'
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 8,
                                                          kControlTagNam0 + i); // 'nam0'-'nam6'
    // 0x6980c8 is an unlabeled data address Ghidra never recognized as a string (no
    // string-oracle entry, single xref) -- treated as the empty placeholder caption it
    // reads as.
    TStaticText* nameControl = RefreshActiveControlThenApplyThemeStyleAndCaption(
        kControlTagNam0 + i, 0, 0xe, 0x2b6b, -2, "");
    nameControl->AssertValid();
    ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameControl, 0, 0xe, 0x2b6b, 0x2b6c);
  }

  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xb, kControlTagMapP); // 'map '
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xd, kControlTagTnam); // 'tnam'
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xe, kControlTagSend); // 'send'

  if (!g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 9, kControlTagCncl); // 'clnc'
    g_pGameFlowState->ResetNationStatusSlotsAndInitializeNameControls(this);
    if (g_pSimMgr->multiplayerSessionRole == 1) {
      g_pGameFlowState->SetDialogModeTagInitAndInvokeNoOpHook();
      RefreshMapAndMessageControlsForCurrentContext();
      g_pGameFlowState->DispatchTurnEventCode9WithTwoTextTokens(
          -0xd, 0, g_pLoungeLocalPlayerNameSharedText_0065c160,
          g_pLoungeLocalPlayerNameSharedText_0065c160);
      g_pGameFlowState->EmitTurnEventEAnd9SessionContextPackets(nullptr);
    }
  } else {
    g_pGameFlowState->RefreshNationStatusLabelsAndCodesForSlotOrAll(-1);
    // The cancel button reads "leave" (0x12) while the local seat is still busy and
    // "disconnect" (0x11) once it is not.
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(
        0x2742,
        g_pGameFlowState->GetNationStatusCodeForSlotOrActiveNation(-1) == kSessionTagBusy ? 0x12
                                                                                          : 0x11,
        kControlTagCncl);
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xc, kSessionTagMess);

    TPicture* coatControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagCoat)); // 'coat'
    coatControl->AssertValid();
    coatControl->SetPictureResourceIdAndRefresh(
        static_cast<short>(g_pSimMgr->GetActiveNationId() + 0x120a), 0);
    coatControl->SetEnabled(1, 0);
    if (g_pGameFlowState->GetNationStatusCodeForSlotOrActiveNation(-1) != kSessionTagBusy) {
      SetPictureResourceIdAndRefresh(0x11f9, 0);
    }
    RefreshMapAndMessageControlsForCurrentContext();
  }

  selectedNationSlot = -1;
  DoIdle(1);

  short messageStringIndex;
  if (g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    messageStringIndex =
        g_pGameFlowState->GetNationStatusCodeForSlotOrActiveNation(-1) == kSessionTagBusy ? 0x24
                                                                                          : 0x10;
  } else {
    messageStringIndex = static_cast<short>(g_pSimMgr->mode == 1 ? 0x10 : 0x18);
  }
  ConfigureUiControlStyleValueAndCaptionFromStringResource(
      static_cast<TStaticText*>(ResolveControlByTag(kSessionTagMess)), 0, 0xe, 0x2b6c, 1, 0x2742,
      messageStringIndex);
  TNoHilitePicture::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0054db40
char TLoungeDialog::DoIdle(int action) {
  (void)action;
  // Per-nation status lamp ('rad0'..'rad6', TNoHilitePicture) and name label
  // ('nam0'..'nam6', TDropShadowText) -- both from MapView.rsrc view 1508.
  bool anyLocalSeat = false;
  for (int nationSlot = 0; nationSlot < TMultiplayerMgr::kMajorNationSessionSlotCount;
       ++nationSlot) {
    int sessionId = g_pGameFlowState->nationSessionIds[nationSlot];
    int statusIndex = 0;
    if (sessionId == 0) {
      statusIndex = 2;
    } else if (sessionId == -2) {
      statusIndex = 3;
    } else {
      switch (g_pGameFlowState->GetNationStatusCodeForSlotOrActiveNation(nationSlot)) {
      case kSessionTagBusy: // 'busy'
        statusIndex = 0;
        break;
      case kSessionTagRedy: // 'redy'
        statusIndex = 1;
        break;
      case kSessionTagUnas: // 'unas'
        statusIndex = 2;
        break;
      case kSessionTagAwol: // 'awol'
        statusIndex = 3;
        break;
      case kSessionTagDead: // 'dead'
      case kSessionTagDeca: // 'deca'
        statusIndex = 4;
        break;
      default:
        break;
      }
    }

    TPicture* statusLamp =
        static_cast<TPicture*>(ResolveControlByTag(kSessionTagRad0 + nationSlot));
    statusLamp->AssertValid();
    if (statusLamp->glyphBase84 != kLoungeStatusGlyphIds[statusIndex]) {
      statusLamp->SetPictureResourceIdAndRefresh(kLoungeStatusGlyphIds[statusIndex], 1);
    }

    bool isLocalSeat =
        g_pGameFlowState->nationSessionIds[nationSlot] == TouchSessionActiveNationId() &&
        g_pGameFlowState->nationSessionIds[nationSlot] != 0;
    if (isLocalSeat) {
      anyLocalSeat = true;
    }

    TDropShadowText* nameLabel =
        static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagNam0 + nationSlot));
    nameLabel->AssertValid();
    CString desiredName;
    CString currentName;
    nameLabel->CopyTextTo(&currentName);
    desiredName = g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(
        &g_pGameFlowState->defaultNationTextSlots[nationSlot]);
    if (currentName.Compare(desiredName) != 0) {
      nameLabel->SetTextAndMaybeRefresh(&desiredName, 1);
      if (statusIndex == 4) {
        ApplyUiTextStyleAndThemeFlags(nameLabel, 0, 0xe, 0x2b67, 0x2b6a);
      } else if (isLocalSeat) {
        ApplyUiTextStyleAndThemeFlags(nameLabel, 0, 0xe, 0x2b6c, 0x2b6b);
      } else {
        ApplyUiTextStyleAndThemeFlags(nameLabel, 0, 0xe, 0x2b6b, 0x2b6c);
      }
    }
  }

  short messageStringIndex;
  if (g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    if (g_pGameFlowState->GetNationStatusCodeForSlotOrActiveNation(-1) == kSessionTagBusy &&
        g_pGameFlowState->fieldF4 != 0) {
      messageStringIndex = 0x24;
      if (glyphBase84 != 0x11f8) {
        SetPictureResourceIdAndRefresh(0x11f8, 1);
      }
    } else {
      messageStringIndex = 0x10;
      if (glyphBase84 != 0x11f9) {
        SetPictureResourceIdAndRefresh(0x11f9, 1);
      }
    }
  } else if (g_pSimMgr->mode == 1 || anyLocalSeat) {
    messageStringIndex = 0x10;
  } else {
    messageStringIndex = static_cast<short>(g_pGlobalMapState != 0 ? 0x2c : 0x18);
  }

  CString messageText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageText, 0x2742,
                                                                  messageStringIndex);
  TStaticText* messageControl = static_cast<TStaticText*>(ResolveControlByTag(kSessionTagMess));
  messageControl->AssertValid();
  messageControl->SetTextAndMaybeRefresh(&messageText, 1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0054dfc0
void TLoungeDialog::TryReplaceRemoteNationSlot(int nationSlot) {
  if (!g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    g_pGameFlowState->DispatchLobbyTextPairEvent8(static_cast<unsigned char>(nationSlot));
    return;
  }

  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->diplomacyEligibilityA0 == 0 || !nation->IsRemote()) {
    return;
  }

  if ((static_cast<unsigned short>(GetAsyncKeyState(VK_CONTROL)) & 0x8000) == 0) {
    QueuePoseMessageDialogForNationSlot(nationSlot);
    return;
  }
  if (g_pSimMgr->multiplayerSessionRole != 1) {
    return;
  }

  CString templateText;
  CString formattedText;
  CString nationName;
  nation->FormatOverlayTerrainLabelText(&nationName);
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&templateText, 0x2742, 0x1b);
  scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(nationName));
  if (g_pViewMgr->ModalMessage(formattedText, g_ptLoungeNationReplacementModalMessage, 0, 1)) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kSessionTagAced, nationSlot, -2); // 'deca'
    g_pGameFlowState->ReplaceNationStateForSlotAndRefreshStatus(nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x0054e1f0
void TLoungeDialog::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x29a) {
    TView* okayControl = ResolveControlByTag(kControlTagOkay);
    okayControl->AssertValid();
    okayControl->SetState(0, 0);
    okayControl->SetEnabled(0, 0);
  }

  if (commandId == kControlTagPick) { // 'pick'
    sourceHandler->AssertValid();
    TryReplaceRemoteNationSlot(static_cast<TMapPreviewView*>(sourceHandler)->pendingNation6C);
  }

  if (commandId == 0x14 || commandId == 0x0a || commandId == 0x22 || commandId == 0x0d) {
    unsigned int controlTag = sourceHandler->controlTag;
    if (controlTag == kControlTagCncl || controlTag == kControlTagCanc) { // 'cncl' / 'canc'
      if (g_pGameFlowState->IsSpecialNationDialogModeActive()) {
        if (g_pGameFlowState->GetNationStatusCodeForSlotOrActiveNation(-1) == kSessionTagBusy) {
          g_pSimMgr->StartNextPhase(); // 'busy'
        } else if (g_pViewMgr->DispatchGameStateEventIfLocalizedPromptAccepted(
                       kControlTagNewg)) { // 'gwen'
          g_pAmbitApplication->CreateAndQueueTurnEventPacketTagGWEN();
        }
      } else {
        unsigned char hasOtherSession = 0;
        for (int slot = 0; slot < TMultiplayerMgr::kMajorNationSessionSlotCount; ++slot) {
          int sessionId = g_pGameFlowState->nationSessionIds[slot];
          if (sessionId != 0 && sessionId != TouchSessionActiveNationId()) {
            hasOtherSession = 1;
          }
        }
        if (g_pSimMgr->multiplayerSessionRole != 1 || hasOtherSession == 0 ||
            g_pViewMgr->DispatchGameStateEventIfLocalizedPromptAccepted(
                kControlTagCgam)) { // 'magc'
          if (g_pSimMgr->multiplayerSessionRole == 1) {
            g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kControlTagCgam, -1, -2);
          }
          g_pGameFlowState->ResetLocalUiStateAndPostTurnEvent5E5();
        }
      }
    } else if (controlTag >= kSessionTagRad0 && controlTag <= kSessionTagRad6) { // 'rad0'..'rad6'
      TryReplaceRemoteNationSlot(static_cast<int>(controlTag - kSessionTagRad0));
    } else if (controlTag >= kControlTagNam0 && controlTag <= kControlTagNam6) { // 'nam0'..'nam6'
      TryReplaceRemoteNationSlot(static_cast<int>(controlTag - kControlTagNam0));
    } else if (controlTag >= kSessionTagPik0 && controlTag <= kSessionTagPik6) { // 'pik0'..'pik6'
      TryReplaceRemoteNationSlot(static_cast<int>(controlTag - kSessionTagPik0));
    } else if (controlTag == kControlTagSend) { // 'send'
      QueuePoseMessageDialogForNationSlot(-1);
    } else if (controlTag == kControlTagOkay) { // 'okay'
      g_pGameFlowState->CloseLobbyDialogAndEmitTurnEvent3();
    } else if (controlTag == kSessionTagJedi) { // 'jedi'
      g_pGameFlowState->EmitTurnEvent10ForFlaggedNationSlots();
    }
  }

  TControl::DoEvent(commandId, sourceHandler, event);
}

namespace {

// RAII wait-cursor guard, same reconstruction as TAssetMgr.cpp's 0x5e0030: EH state 0
// opens with an inlined AfxGetApp()->BeginWaitCursor() and unwinds with the matching
// EndWaitCursor().
} // namespace

// Under a wait cursor: restamp the 'tnam' caption from the host game name, re-rasterize
// and palette-mask the 'map ' preview then invalidate its bounds, load the lounge
// message string (0x2742/0x10) into 'mess', and refresh the dialog.
// FUNCTION: IMPERIALISM 0x0054e4c0
void TLoungeDialog::RefreshMapAndMessageControlsForCurrentContext() {
  TScopedWaitCursor waitCursor;
  TStaticText* nameControl = RefreshActiveControlThenApplyThemeStyleAndCaption(
      kControlTagTnam, 0, 0xe, 0x2b6b, 1,
      static_cast<const char*>(g_pGameFlowState->gameNameString));
  nameControl->AssertValid();
  ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameControl, 0, 0xc, 0x2b6b, 0x2b6c);
  TMapPreviewView* mapControl = static_cast<TMapPreviewView*>(ResolveControlByTag(kControlTagMapP));
  mapControl->AssertValid();
  mapControl->TakeSatellitePhoto(0);
  mapControl->EnhancePhoto();
  CRect mapBounds;
  mapControl->QueryBounds(&mapBounds);
  RECT invalidBounds = mapBounds;
  InvalidateCityDialogRectRegion(&invalidBounds, 1);
  TStaticText* messControl = (TStaticText*)ResolveControlByTag(kSessionTagMess);
  messControl->AssertValid();
  CString messageText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageText, 0x2742, 0x10);
  messControl->SetTextAndMaybeRefresh(&messageText, 1);
  RefreshControl();
}
