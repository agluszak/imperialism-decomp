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
// SYNTHETIC: IMPERIALISM 0x004f8ec0
// TOffersPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8f50
// TOffersPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOffersPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004f8f70
TOffersPanelView::TOffersPanelView() : TPanelView(), acceptButton(0), rejectButton(0) {}

// SYNTHETIC: IMPERIALISM 0x004f8fa0
// TOffersPanelView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004f8fd0
TOffersPanelView::~TOffersPanelView() {}

// FUNCTION: IMPERIALISM 0x004f8ff0
void TOffersPanelView::DoPostCreate(int arg) {
  TPanelView::DoPostCreate(arg);

  acceptButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagAcce));
  acceptButton->AssertValid();
  rejectButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagReje));
  rejectButton->AssertValid();
  acceptButton->timingWord92 = 0x1388;
  rejectButton->timingWord92 = 0x1388;

  TextStyle sharedStyle;
  BuildUiTextStyleDescriptor(&sharedStyle, 0, 0, 0x2b68);

  // 'prop'/'text' are TDeluxeText controls (see the TDeluxeText class-recovery note in
  // TSpecialQuitPicture.cpp): their vtable slots 0x1e4/0x1c4 match
  // SetTextStyle/SetTextAlignmentAndMaybeRefresh exactly.
  TDeluxeText* propControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagProp));
  propControl->AssertValid();
  propControl->SetTextStyle(sharedStyle, 0);
  propControl->shadowTextColor9C = sharedStyle.textColor;
  propControl->dropShadowEnabledA0 = true;
  propControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  TDeluxeText* textControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagText));
  textControl->AssertValid();
  textControl->SetTextStyle(sharedStyle, 0);
  textControl->shadowTextColor9C = sharedStyle.textColor;
  textControl->dropShadowEnabledA0 = true;
  textControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  CString acceHint;
  g_pSimMgr->GetString(0x274a, 6, &acceHint);
  SetControlHoverHelpText(acceHint, acceptButton);
  CString rejeHint;
  g_pSimMgr->GetString(0x274a, 7, &rejeHint);
  SetControlHoverHelpText(rejeHint, rejectButton);

  // Blanks the panel's own hover-help text (SetControlHoverHelpText's callee target
  // decodes to the real ported SetControlHoverHelpText/TView::SetHoverHelpText, not the
  // stale "ApplySharedStringToControlState" symbols.csv name).
  SetControlHoverHelpText(CString(), this);
}

// FUNCTION: IMPERIALISM 0x004f9300
void TOffersPanelView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId != 5 && commandId == 0xa) {
    if (tag == kControlTagAcce || tag == kControlTagReje) {
      lastNegotiationResponseTag64 = tag;
    }
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f9350
void TOffersPanelView::DoKeyEvent(TToolboxEvent* event) {
  int commandCode = event->commandCode;
  if (commandCode == kUiKeyEnter || commandCode == kUiKeyReturn) {
    TPictureButton* button = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagAcce));
    if (button == 0) {
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(button->timingWord92, 0, 1);
    QueueDeferredUiEventPacket(this, 0xa, button);
  } else if (commandCode == kUiKeyEscape) {
    TPictureButton* button = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagReje));
    if (button == 0) {
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(button->timingWord92, 0, 1);
    QueueDeferredUiEventPacket(this, 0xa, button);
  }
}

// Pure forward to the plain TView release handling; the panel adds nothing of its own.
// FUNCTION: IMPERIALISM 0x004f9420
char TOffersPanelView::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  return TView::HandleMouseUp(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004f9450
char TOffersPanelView::PoseOffer(short sourceNation, short targetNation, short offerType) {
  ResolveControlByTag(kControlTagOffr);
  CString templateText;
  CString proposalText;
  CString targetNationName;
  CString sourceNationName;

  g_apTerrainTypeDescriptorTable[targetNation]->FormatOverlayTerrainLabelText(&targetNationName);
  g_apTerrainTypeDescriptorTable[sourceNation]->FormatOverlayTerrainLabelText(&sourceNationName);
  diplomacyMapView60->frameRegionSelectorAt98 = targetNation;

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
            g_pDiplomacyTurnStateManager->IsNationPairAtWar(
                static_cast<NationSlot>(nation), static_cast<NationSlot>(targetNation)) &&
            !g_pDiplomacyTurnStateManager->IsNationPairAtWar(static_cast<NationSlot>(sourceNation),
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
            g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
                static_cast<NationSlot>(sourceNation), static_cast<NationSlot>(nation)) ==
                kDiplomacyRelationshipAlliance &&
            g_pDiplomacyTurnStateManager->IsNationPairAtWar(
                static_cast<NationSlot>(nation), static_cast<NationSlot>(targetNation))) {
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
  TView* sheet = ResolveControlByTag(kControlTagShee);
  TView* wait = ResolveControlByTag(kControlTagWait);
  TDeluxeText* message;
  if (isNotice) {
    message = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagText));
    message->AssertValid();
    sheet->Locate(g_diplomacyPopupOffscreenPosition_006a3020, 1);
    wait->Locate(g_diplomacyPopupVisiblePosition_006a2fe0, 1);
  } else {
    message = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagProp));
    message->AssertValid();
    wait->Locate(g_diplomacyPopupOffscreenPosition_006a3020, 1);
    sheet->Locate(g_diplomacyPopupVisiblePosition_006a2fe0, 1);
  }
  message->UpdateTextEntrySharedStringAndMaybeNotify(&proposalText, 1);
  message->CenterVertically(1);
  RefreshControl();
  ForceRedraw();

  // The original blocks only for interactive offers. DoEvent writes the selected
  // FourCC into this field when the accept/reject hotspot is activated.
  if (!isNotice) {
    lastNegotiationResponseTag64 = 0;
    while (lastNegotiationResponseTag64 == 0) {
      PumpUiMessagesAndBackgroundTasks(1);
    }
    if (lastNegotiationResponseTag64 == static_cast<int>(kControlTagAcce)) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f9a60
char TOffersPanelView::PoseWarOffer(short sourceNationSlot, int minorNationSlot,
                                    int enemyNationSlot, int promptCode) {
  CString formattedMessage;
  CString templateText(g_szEmptyString);
  CString minorNationName;
  CString enemyNationName;

  TDeluxeText* proposalText = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagProp));
  if (proposalText == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUDiplomacyViews_00696AE0, 0xca0);
  }

  g_apTerrainTypeDescriptorTable[minorNationSlot]->FormatOverlayTerrainLabelText(&minorNationName);
  g_apTerrainTypeDescriptorTable[enemyNationSlot]->FormatOverlayTerrainLabelText(&enemyNationName);

  bool addsEntanglements = false;
  int nationSlot;
  if (promptCode == 0x0a) {
    for (nationSlot = 0; nationSlot < 7 && !addsEntanglements; ++nationSlot) {
      if (nationSlot != enemyNationSlot &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, minorNationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, sourceNationSlot) == 0) {
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
      if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
              static_cast<short>(enemyNationSlot), static_cast<short>(nationSlot)) ==
              kDiplomacyRelationshipAlliance &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, sourceNationSlot) == 0) {
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
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, minorNationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, sourceNationSlot) == 0) {
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
      if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
              static_cast<short>(minorNationSlot), static_cast<short>(nationSlot)) ==
              kDiplomacyRelationshipAlliance &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, sourceNationSlot) == 0) {
        addsEntanglements = true;
      }
    }
    g_pSimMgr->GetString(0x2729, 2, &templateText);
    scanBracketExpressions(
        g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
        static_cast<LPCSTR>(enemyNationName), static_cast<LPCSTR>(minorNationName),
        static_cast<LPCSTR>(enemyNationName), static_cast<LPCSTR>(minorNationName));
  }

  TView* sheet = ResolveControlByTag(kControlTagShee);
  TView* wait = ResolveControlByTag(kControlTagWait);
  wait->Locate(g_diplomacyPopupOffscreenPosition_006a3020, 0);
  sheet->Locate(g_diplomacyPopupVisiblePosition_006a2fe0, 1);
  proposalText->UpdateTextEntrySharedStringAndMaybeNotify(&formattedMessage, 1);
  proposalText->CenterVertically(1);
  RefreshControl();
  ForceRedraw();

  lastNegotiationResponseTag64 = 0;
  while (lastNegotiationResponseTag64 == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
  }
  return lastNegotiationResponseTag64 == static_cast<int>(kControlTagAcce);
}
