#include <mbstring.h>
#include "game/TScopedWaitCursor.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_screens.h"
#include "game/net/TLoungeDialog.h"
#include "game/ui_core/TLanguageMgr.h"

#include "game/core/CString.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TApplication.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/gfx/TResourceMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/net/TPoseMessageDialog.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/net_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0044fb60
TLoungeDialog::~TLoungeDialog() {}

IMPLEMENT_DYNCREATE(TLoungeDialog, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0054d6f0
void TLoungeDialog::Free() {
  if (g_nSaveFormatVersion != kControlTagMoil) { // 'Moil'
    g_pGameFlowState->InstallCohandler(this, false);
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x0054d730
void TLoungeDialog::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  g_pGameFlowState->InstallCohandler(this, true);

  TInfoBarText* lablControl = static_cast<TInfoBarText*>(FindSubView(kSessionTagLabl));
  g_pCursorControlPanel = lablControl;
  lablControl->AssertValid();
  lablControl->SetTextStyle(0, 0xe, 0x2b6b);
  lablControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  lablControl->SetJustification(1, false);

  for (int i = 0; i < 7; ++i) {
    SetTaggedStringAndApply(0x2742, 6,
                            kSessionTagRad0 + i); // 'rad0'-'rad6'
    SetTaggedStringAndApply(0x2742, 7,
                            kSessionTagPik0 + i); // 'pik0'-'pik6'
    SetTaggedStringAndApply(0x2742, 8,
                            kControlTagNam0 + i); // 'nam0'-'nam6'
    TStaticText* nameControl = RefreshAndTheme(kControlTagNam0 + i, 0, 0xe, 0x2b6b, -2, "");
    nameControl->AssertValid();
    ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameControl, 0, 0xe, 0x2b6b, 0x2b6c);
  }

  SetTaggedStringAndApply(0x2742, 0xb, kControlTagMapP); // 'map '
  SetTaggedStringAndApply(0x2742, 0xd, kControlTagTnam); // 'tnam'
  SetTaggedStringAndApply(0x2742, 0xe, kControlTagSend); // 'send'

  if (!g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    SetTaggedStringAndApply(0x2742, 9, kControlTagCncl); // 'clnc'
    g_pGameFlowState->ResetLobbySlots(this);
    if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
      g_pGameFlowState->SetDialogModeTagInitAndInvokeNoOpHook();
      YouHaveNewGameData();
      g_pGameFlowState->SendGpSelection(-0xd, 0, g_pLoungeLocalPlayerNameSharedText,
                                        g_pLoungeLocalPlayerNameSharedText);
      g_pGameFlowState->EmitTurnEventEAnd9SessionContextPackets(NULL);
    }
  } else {
    g_pGameFlowState->RecalcPlayerName(-1);
    SetTaggedStringAndApply(0x2742,
                            g_pGameFlowState->GetPlayerStatus(-1) == kSessionTagBusy ? 0x12 : 0x11,
                            kControlTagCncl);
    SetTaggedStringAndApply(0x2742, 0xc, kSessionTagMess);

    TPicture* coatControl = static_cast<TPicture*>(FindSubView(kControlTagCoat)); // 'coat'
    coatControl->AssertValid();
    coatControl->SetPictureRsrcID(static_cast<short>(g_pSimMgr->GetPlayerCountry() + 0x120a), 0);
    coatControl->Show(1, 0);
    if (g_pGameFlowState->GetPlayerStatus(-1) != kSessionTagBusy) {
      SetPictureRsrcID(0x11f9, 0);
    }
    YouHaveNewGameData();
  }

  selectedNationSlot = -1;
  DoIdle(1);

  short messageStringIndex;
  if (g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    messageStringIndex = g_pGameFlowState->GetPlayerStatus(-1) == kSessionTagBusy ? 0x24 : 0x10;
  } else {
    messageStringIndex = static_cast<short>(g_pSimMgr->mode == kGamePhaseStartup ? 0x10 : 0x18);
  }
  ConfigureControlFromStrings(static_cast<TStaticText*>(FindSubView(kSessionTagMess)), 0, 0xe,
                              0x2b6c, 1, 0x2742, messageStringIndex);
  TNoHilitePicture::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0054db40
bool TLoungeDialog::DoIdle(int action) {
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
      switch (g_pGameFlowState->GetPlayerStatus(nationSlot)) {
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

    TPicture* statusLamp = static_cast<TPicture*>(FindSubView(kSessionTagRad0 + nationSlot));
    statusLamp->AssertValid();
    if (statusLamp->glyphBase != kLoungeStatusGlyphIds[statusIndex]) {
      statusLamp->SetPictureRsrcID(kLoungeStatusGlyphIds[statusIndex], 1);
    }

    bool isLocalSeat =
        g_pGameFlowState->nationSessionIds[nationSlot] == TouchSessionActiveNationId() &&
        g_pGameFlowState->nationSessionIds[nationSlot] != 0;
    if (isLocalSeat) {
      anyLocalSeat = true;
    }

    TDropShadowText* nameLabel =
        static_cast<TDropShadowText*>(FindSubView(kControlTagNam0 + nationSlot));
    nameLabel->AssertValid();
    CString desiredName;
    CString currentName;
    nameLabel->CopyTextTo(&currentName);
    desiredName =
        g_pLanguageMgr->StripCodeStr(g_pGameFlowState->defaultNationTextSlots[nationSlot]);
    if (currentName.Compare(desiredName) != 0) {
      nameLabel->SetTextAndMaybeRefresh(&desiredName, true);
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
    if (g_pGameFlowState->GetPlayerStatus(-1) == kSessionTagBusy &&
        g_pGameFlowState->networkSavePending != 0) {
      messageStringIndex = 0x24;
      if (glyphBase != 0x11f8) {
        SetPictureRsrcID(0x11f8, 1);
      }
    } else {
      messageStringIndex = 0x10;
      if (glyphBase != 0x11f9) {
        SetPictureRsrcID(0x11f9, 1);
      }
    }
  } else if (g_pSimMgr->mode == kGamePhaseStartup || anyLocalSeat) {
    messageStringIndex = 0x10;
  } else {
    messageStringIndex = static_cast<short>(g_pGlobalMapState != 0 ? 0x2c : 0x18);
  }

  CString messageText;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageText, 0x2742, messageStringIndex);
  TStaticText* messageControl = static_cast<TStaticText*>(FindSubView(kSessionTagMess));
  messageControl->AssertValid();
  messageControl->SetTextAndMaybeRefresh(&messageText, true);
  return false;
}

// FUNCTION: IMPERIALISM 0x0054dfc0
void TLoungeDialog::NationalClick(int nationSlot) {
  if (!g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    g_pGameFlowState->DispatchLobbyTextPairEvent8(static_cast<unsigned char>(nationSlot));
    return;
  }

  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->diplomacyEligibility == 0 || !nation->IsRemote()) {
    return;
  }

  if ((static_cast<unsigned short>(GetAsyncKeyState(VK_CONTROL)) & 0x8000) == 0) {
    QueuePoseMessageDialogForNationSlot(nationSlot);
    return;
  }
  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleHost) {
    return;
  }

  CString templateText;
  CString formattedText;
  CString nationName;
  nation->FormatOverlayTerrainLabelText(&nationName);
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&templateText, 0x2742, 0x1b);
  scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(nationName));
  if (g_pViewMgr->ModalMessage(formattedText, g_ptLoungeNationReplacementModalMessage, 0, 1)) {
    g_pGameFlowState->SendGameControl(kSessionTagAced, nationSlot, -2); // 'deca'
    g_pGameFlowState->DehumanizePlayer(nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x0054e1f0
void TLoungeDialog::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x29a) {
    TView* okayControl = FindSubView(kControlTagOkay);
    okayControl->AssertValid();
    okayControl->ViewEnable(0, 0);
    okayControl->Show(0, 0);
  }

  if (commandId == kControlTagPick) { // 'pick'
    sourceHandler->AssertValid();
    NationalClick(static_cast<TMapPreviewView*>(sourceHandler)->pendingNation);
  }

  if (commandId == 0x14 || commandId == 0x0a || commandId == 0x22 || commandId == 0x0d) {
    unsigned int controlTag = sourceHandler->controlTag;
    if (controlTag == kControlTagCncl || controlTag == kControlTagCanc) { // 'cncl' / 'canc'
      if (g_pGameFlowState->IsSpecialNationDialogModeActive()) {
        if (g_pGameFlowState->GetPlayerStatus(-1) == kSessionTagBusy) {
          g_pSimMgr->StartNextPhase();                                // 'busy'
        } else if (g_pViewMgr->ConfirmGameControl(kControlTagNewg)) { // 'gwen'
          g_pAmbitApplication->CreateAndQueueTurnEventPacketTagGWEN();
        }
      } else {
        bool hasOtherSession = false;
        for (int slot = 0; slot < TMultiplayerMgr::kMajorNationSessionSlotCount; ++slot) {
          int sessionId = g_pGameFlowState->nationSessionIds[slot];
          if (sessionId != 0 && sessionId != TouchSessionActiveNationId()) {
            hasOtherSession = true;
          }
        }
        if (g_pSimMgr->multiplayerSessionRole != kSessionRoleHost || !hasOtherSession ||
            g_pViewMgr->ConfirmGameControl(kControlTagCgam)) { // 'magc'
          if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
            g_pGameFlowState->SendGameControl(kControlTagCgam, -1, -2);
          }
          g_pGameFlowState->ResetAndShowMultiplayerSetup();
        }
      }
    } else if (controlTag >= kSessionTagRad0 && controlTag <= kSessionTagRad6) { // 'rad0'..'rad6'
      NationalClick(static_cast<int>(controlTag - kSessionTagRad0));
    } else if (controlTag >= kControlTagNam0 && controlTag <= kControlTagNam6) { // 'nam0'..'nam6'
      NationalClick(static_cast<int>(controlTag - kControlTagNam0));
    } else if (controlTag >= kSessionTagPik0 && controlTag <= kSessionTagPik6) { // 'pik0'..'pik6'
      NationalClick(static_cast<int>(controlTag - kSessionTagPik0));
    } else if (controlTag == kControlTagSend) { // 'send'
      QueuePoseMessageDialogForNationSlot(-1);
    } else if (controlTag == kControlTagOkay) { // 'okay'
      g_pGameFlowState->CloseLobbyDialogAndEmitTurnEvent3();
    } else if (controlTag == kSessionTagJedi) { // 'jedi'
      g_pGameFlowState->SendGoAheadMessage();
    }
  }

  TControl::DoEvent(commandId, sourceHandler, event);
}

namespace {} // namespace

// FUNCTION: IMPERIALISM 0x0054e4c0
void TLoungeDialog::YouHaveNewGameData() {
  TScopedWaitCursor waitCursor;
  TStaticText* nameControl =
      RefreshAndTheme(kControlTagTnam, 0, 0xe, 0x2b6b, 1,
                      static_cast<const char*>(g_pGameFlowState->gameNameString));
  nameControl->AssertValid();
  ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameControl, 0, 0xc, 0x2b6b, 0x2b6c);
  TMapPreviewView* mapControl = static_cast<TMapPreviewView*>(FindSubView(kControlTagMapP));
  mapControl->AssertValid();
  mapControl->TakeSatellitePhoto(0);
  mapControl->EnhancePhoto();
  CRect mapBounds;
  mapControl->GetFrame(&mapBounds);
  RECT invalidBounds = mapBounds;
  InvalidateCityDialogRectRegion(&invalidBounds, 1);
  TStaticText* messControl = (TStaticText*)FindSubView(kSessionTagMess);
  messControl->AssertValid();
  CString messageText;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageText, 0x2742, 0x10);
  messControl->SetTextAndMaybeRefresh(&messageText, true);
  RefreshControl();
}
