#include "game/diplomacy_ui/TOffersPanelView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/ui_tags_city.h"

#include "game/ui_widgets/TDeluxeText.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_screens/TPictureButton.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TUiEvent.h"
#include "game/globals/global_types.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/ui_message_pump.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TOffersPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004f8f70
TOffersPanelView::TOffersPanelView() : acceptButton(0), rejectButton(0) {}

// FUNCTION: IMPERIALISM 0x004f8fd0
TOffersPanelView::~TOffersPanelView() {}

// FUNCTION: IMPERIALISM 0x004f8ff0
void TOffersPanelView::DoPostCreate(int arg) {
  TPanelView::DoPostCreate(arg);

  acceptButton = static_cast<TPictureButton*>(FindSubView(kControlTagAcce));
  acceptButton->AssertValid();
  rejectButton = static_cast<TPictureButton*>(FindSubView(kControlTagReje));
  rejectButton->AssertValid();
  acceptButton->clickSoundId = 0x1388;
  rejectButton->clickSoundId = 0x1388;

  TextStyle sharedStyle;
  BuildUiTextStyleDescriptor(&sharedStyle, 0, 0, 0x2b68);

  TDeluxeText* propControl = static_cast<TDeluxeText*>(FindSubView(kControlTagProp));
  propControl->AssertValid();
  propControl->SetTextStyle(sharedStyle, false);
  propControl->shadowTextColor = sharedStyle.textColor;
  propControl->dropShadowEnabled = true;
  propControl->SetJustification(1, false);

  TDeluxeText* textControl = static_cast<TDeluxeText*>(FindSubView(kControlTagText));
  textControl->AssertValid();
  textControl->SetTextStyle(sharedStyle, false);
  textControl->shadowTextColor = sharedStyle.textColor;
  textControl->dropShadowEnabled = true;
  textControl->SetJustification(1, false);

  CString acceHint;
  g_pSimMgr->GetString(0x274a, 6, &acceHint);
  SetControlHoverHelpText(acceHint, acceptButton);
  CString rejeHint;
  g_pSimMgr->GetString(0x274a, 7, &rejeHint);
  SetControlHoverHelpText(rejeHint, rejectButton);

  SetControlHoverHelpText(CString(), this);
}

// FUNCTION: IMPERIALISM 0x004f9300
void TOffersPanelView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId != 5 && commandId == 0xa) {
    if (tag == kControlTagAcce || tag == kControlTagReje) {
      lastNegotiationResponseTag = tag;
    }
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f9350
void TOffersPanelView::DoKeyEvent(TToolboxEvent* event) {
  int commandCode = event->commandCode;
  if (commandCode == kUiKeyEnter || commandCode == kUiKeyReturn) {
    TPictureButton* button = static_cast<TPictureButton*>(FindSubView(kControlTagAcce));
    if (button == 0) {
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(button->clickSoundId, 0, 1);
    QueueDeferredUiEventPacket(this, 0xa, button);
  } else if (commandCode == kUiKeyEscape) {
    TPictureButton* button = static_cast<TPictureButton*>(FindSubView(kControlTagReje));
    if (button == 0) {
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(button->clickSoundId, 0, 1);
    QueueDeferredUiEventPacket(this, 0xa, button);
  }
}

// Pure forward to the plain TView release handling; the panel adds nothing of its own.
// FUNCTION: IMPERIALISM 0x004f9420
char TOffersPanelView::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  return TView::HandleMouseUp(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004f9450
bool TOffersPanelView::PoseOffer(short sourceNation, short targetNation, short offerType) {
  FindSubView(kControlTagOffr);
  CString templateText;
  CString proposalText;
  CString targetNationName;
  CString sourceNationName;

  g_apTerrainTypeDescriptorTable[targetNation]->FormatOverlayTerrainLabelText(&targetNationName);
  g_apTerrainTypeDescriptorTable[sourceNation]->FormatOverlayTerrainLabelText(&sourceNationName);
  diplomacyMapView->frameRegionSelector = targetNation;

  bool hasEntanglements = false;

  if (offerType == 0x29a) {
    g_pSimMgr->GetString(0x2742, 0, &proposalText);
  } else {
    switch (offerType) {
    case kDiplomacyProposalJoinEmpire:
      g_pSimMgr->GetString(0x274a, 0, &templateText);
      scanBracketExpressions(g_pSimMgr, &proposalText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(targetNationName));
      break;
    case kDiplomacyProposalAlliance: {
      for (int nation = 0; nation < 7 && !hasEntanglements; ++nation) {
        if (nation != sourceNation && nation != targetNation &&
            g_pDiplomacyTurnStateManager->AreAtWar(static_cast<NationSlot>(nation),
                                                   static_cast<NationSlot>(targetNation)) &&
            !g_pDiplomacyTurnStateManager->AreAtWar(static_cast<NationSlot>(sourceNation),
                                                    static_cast<NationSlot>(nation))) {
          hasEntanglements = true;
        }
      }
      if (hasEntanglements) {
        g_pSimMgr->GetString(0x274a, 8, &templateText);
      } else {
        g_pSimMgr->GetString(0x274a, 1, &templateText);
      }
      scanBracketExpressions(g_pSimMgr, &proposalText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(targetNationName));
      break;
    }
    case kDiplomacyProposalNonAggressionPact:
      g_pSimMgr->GetString(0x274a, 2, &templateText);
      scanBracketExpressions(g_pSimMgr, &proposalText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(targetNationName));
      break;
    case kDiplomacyProposalPeaceTreaty: {
      for (int nation = 0; nation < 7 && !hasEntanglements; ++nation) {
        if (nation != sourceNation && nation != targetNation &&
            g_pDiplomacyTurnStateManager->GetTreatyStatus(static_cast<NationSlot>(sourceNation),
                                                          static_cast<NationSlot>(nation)) ==
                kDiplomacyRelationshipAlliance &&
            g_pDiplomacyTurnStateManager->AreAtWar(static_cast<NationSlot>(nation),
                                                   static_cast<NationSlot>(targetNation))) {
          hasEntanglements = true;
        }
      }
      if (hasEntanglements) {
        g_pSimMgr->GetString(0x274a, 9, &templateText);
      } else {
        g_pSimMgr->GetString(0x274a, 3, &templateText);
      }
      scanBracketExpressions(g_pSimMgr, &proposalText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(targetNationName));
      break;
    }
    case kDiplomacyProposalJoinEmpireWithWarEntanglements:
      g_pSimMgr->GetString(0x274a, 4, &templateText);
      scanBracketExpressions(g_pSimMgr, &proposalText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(targetNationName),
                             static_cast<LPCSTR>(targetNationName));
      break;
    }
  }

  bool isNotice = offerType == 0x29a;
  TView* sheet = FindSubView(kControlTagShee);
  TView* wait = FindSubView(kControlTagWait);
  TDeluxeText* message;
  if (isNotice) {
    message = static_cast<TDeluxeText*>(FindSubView(kControlTagText));
    message->AssertValid();
    sheet->Locate(g_diplomacyPopupOffscreenPosition, true);
    wait->Locate(g_diplomacyPopupVisiblePosition, true);
  } else {
    message = static_cast<TDeluxeText*>(FindSubView(kControlTagProp));
    message->AssertValid();
    wait->Locate(g_diplomacyPopupOffscreenPosition, true);
    sheet->Locate(g_diplomacyPopupVisiblePosition, true);
  }
  message->UpdateTextEntrySharedStringAndMaybeNotify(&proposalText, true);
  message->CenterVertically(true);
  RefreshControl();
  ForceRedraw();

  if (!isNotice) {
    lastNegotiationResponseTag = 0;
    while (lastNegotiationResponseTag == 0) {
      PumpUiMessagesAndBackgroundTasks(1);
    }
    if (lastNegotiationResponseTag == static_cast<int>(kControlTagAcce)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004f9a60
char TOffersPanelView::PoseWarOffer(short sourceNationSlot, int minorNationSlot,
                                    int enemyNationSlot, int promptCode) {
  CString formattedMessage;
  CString templateText(g_szEmptyString);
  CString minorNationName;
  CString enemyNationName;

  TDeluxeText* proposalText = static_cast<TDeluxeText*>(FindSubView(kControlTagProp));
  if (proposalText == 0) {
    FailNilPointerWithAssert(s_SourcePathUDiplomacyViews, 0xca0);
  }

  g_apTerrainTypeDescriptorTable[minorNationSlot]->FormatOverlayTerrainLabelText(&minorNationName);
  g_apTerrainTypeDescriptorTable[enemyNationSlot]->FormatOverlayTerrainLabelText(&enemyNationName);

  bool addsEntanglements = false;
  int nationSlot;
  if (promptCode == 0x0a) {
    for (nationSlot = 0; nationSlot < 7 && !addsEntanglements; ++nationSlot) {
      if (nationSlot != enemyNationSlot &&
          g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, minorNationSlot) &&
          !g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, sourceNationSlot)) {
        addsEntanglements = true;
      }
    }
    g_pSimMgr->GetString(0x2729, addsEntanglements ? 4 : 0, &templateText);
    scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(enemyNationName),
                           static_cast<LPCSTR>(minorNationName),
                           static_cast<LPCSTR>(enemyNationName));
  } else if (promptCode == 0x14) {
    for (nationSlot = 0; nationSlot < 7 && !addsEntanglements; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->GetTreatyStatus(static_cast<short>(enemyNationSlot),
                                                        static_cast<short>(nationSlot)) ==
              kDiplomacyRelationshipAlliance &&
          !g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, sourceNationSlot)) {
        addsEntanglements = true;
      }
    }
    g_pSimMgr->GetString(0x2729, addsEntanglements ? 5 : 1, &templateText);
    scanBracketExpressions(
        g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
        static_cast<LPCSTR>(enemyNationName), static_cast<LPCSTR>(minorNationName),
        static_cast<LPCSTR>(minorNationName), static_cast<LPCSTR>(enemyNationName));
  } else if (promptCode == 0x0b) {
    for (nationSlot = 0; nationSlot < 7 && !addsEntanglements; ++nationSlot) {
      if (nationSlot != enemyNationSlot &&
          g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, minorNationSlot) &&
          !g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, sourceNationSlot)) {
        addsEntanglements = true;
      }
    }
    g_pSimMgr->GetString(0x2729, addsEntanglements ? 8 : 3, &templateText);
    scanBracketExpressions(
        g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
        static_cast<LPCSTR>(minorNationName), static_cast<LPCSTR>(enemyNationName),
        static_cast<LPCSTR>(minorNationName), static_cast<LPCSTR>(minorNationName));
  } else {
    for (nationSlot = 0; nationSlot < 7 && !addsEntanglements; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->GetTreatyStatus(static_cast<short>(minorNationSlot),
                                                        static_cast<short>(nationSlot)) ==
              kDiplomacyRelationshipAlliance &&
          !g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, sourceNationSlot)) {
        addsEntanglements = true;
      }
    }
    g_pSimMgr->GetString(0x2729, 2, &templateText);
    scanBracketExpressions(
        g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
        static_cast<LPCSTR>(enemyNationName), static_cast<LPCSTR>(minorNationName),
        static_cast<LPCSTR>(enemyNationName), static_cast<LPCSTR>(minorNationName));
  }

  TView* sheet = FindSubView(kControlTagShee);
  TView* wait = FindSubView(kControlTagWait);
  wait->Locate(g_diplomacyPopupOffscreenPosition, false);
  sheet->Locate(g_diplomacyPopupVisiblePosition, true);
  proposalText->UpdateTextEntrySharedStringAndMaybeNotify(&formattedMessage, true);
  proposalText->CenterVertically(true);
  RefreshControl();
  ForceRedraw();

  lastNegotiationResponseTag = 0;
  while (lastNegotiationResponseTag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
  }
  return lastNegotiationResponseTag == static_cast<int>(kControlTagAcce);
}
