#include "game/TOffersPanelView.h"

#include "game/TDeluxeText.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004f8ec0
// TOffersPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8f50
// TOffersPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOffersPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004f8f70
TOffersPanelView::TOffersPanelView() : TPanelView(), acceptText(0), rejectText(0) {}

// SYNTHETIC: IMPERIALISM 0x004f8fa0
// TOffersPanelView::`scalar deleting destructor'
TOffersPanelView::~TOffersPanelView() {}

// FUNCTION: IMPERIALISM 0x004f8ff0
void TOffersPanelView::DoPostCreate(int arg) {
  TPanelView::DoPostCreate(arg);

  acceptText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagAcce));
  acceptText->AssertValid();
  rejectText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagReje));
  rejectText->AssertValid();
  acceptText->textOptionFlags = 0x1388;
  rejectText->textOptionFlags = 0x1388;

  TUiTextStyleDescriptor sharedStyle;
  BuildUiTextStyleDescriptor(&sharedStyle, 0, 0, 0x2b68);

  // 'prop'/'text' are TDeluxeText controls (see the TDeluxeText class-recovery note in
  // TSpecialQuitPicture.cpp): their vtable slots 0x1e4/0x1c4 match
  // ApplyTextStyleDescriptorAndMaybeRefresh/SetTextAlignmentAndMaybeRefresh exactly.
  TDeluxeText* propControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagProp));
  propControl->AssertValid();
  propControl->ApplyTextStyleDescriptorAndMaybeRefresh(&sharedStyle, 0);
  propControl->shadowTextColor9C = sharedStyle.textColor;
  propControl->dropShadowEnabledA0 = true;
  propControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  TDeluxeText* textControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagText));
  textControl->AssertValid();
  textControl->ApplyTextStyleDescriptorAndMaybeRefresh(&sharedStyle, 0);
  textControl->shadowTextColor9C = sharedStyle.textColor;
  textControl->dropShadowEnabledA0 = true;
  textControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  CString acceHint;
  g_pSimMgr->GetString(0x274a, 6, &acceHint);
  SetControlHoverHelpText(acceHint, acceptText);
  CString rejeHint;
  g_pSimMgr->GetString(0x274a, 7, &rejeHint);
  SetControlHoverHelpText(rejeHint, rejectText);

  // Blanks the panel's own hover-help text (SetControlHoverHelpText's callee target
  // decodes to the real ported SetControlHoverHelpText/TView::SetHoverHelpText, not the
  // stale "ApplySharedStringToControlState" symbols.csv name).
  SetControlHoverHelpText(CString(), this);
}

// FUNCTION: IMPERIALISM 0x004f9300
void TOffersPanelView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId == 5 || (commandId == 0xa && (tag == kControlTagAcce || tag == kControlTagReje))) {
    lastNegotiationResponseTag64 = tag;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f9350
void TOffersPanelView::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x004f9420
char TOffersPanelView::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f9450
char TOffersPanelView::PoseOffer(short sourceNation, short targetNation, short offerType) {
  CString proposalText;

  if (offerType == 0x29a) {
    g_pSimMgr->GetString(0x2742, 0, &proposalText);
  } else {
    short stringIndex = 0;
    switch (offerType) {
    case 0x12d:
      stringIndex = 0;
      break;
    case 0x12e:
      stringIndex = 1;
      break;
    case 0x12f:
      stringIndex = 2;
      break;
    case 0x130:
      stringIndex = 3;
      break;
    case 0x132:
      stringIndex = 4;
      break;
    }
    g_pSimMgr->GetString(0x274a, stringIndex, &proposalText);
  }

  TView* sheet = ResolveControlByTag('shee');
  TView* wait = ResolveControlByTag('wait');
  TDeluxeText* message = static_cast<TDeluxeText*>(
      ResolveControlByTag(offerType == 0x29a ? kControlTagText : kControlTagProp));
  message->AssertValid();
  message->UpdateTextEntrySharedStringAndMaybeNotify(&proposalText, 1);
  message->RefreshControl();
  sheet->RefreshControl();
  wait->RefreshControl();

  // The original blocks only for interactive offers. DoEvent writes the selected
  // FourCC into this field when the accept/reject hotspot is activated.
  if (offerType != 0x29a) {
    lastNegotiationResponseTag64 = 0;
    while (lastNegotiationResponseTag64 == 0) {
      PumpUiMessagesAndBackgroundTasks(1);
    }
  }
  (void)sourceNation;
  (void)targetNation;
  return lastNegotiationResponseTag64 == static_cast<int>(kControlTagAcce);
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
              static_cast<short>(enemyNationSlot), static_cast<short>(nationSlot)) == 2 &&
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
              static_cast<short>(minorNationSlot), static_cast<short>(nationSlot)) == 2 &&
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

  TView* sheet = ResolveControlByTag('shee');
  TView* wait = ResolveControlByTag('wait');
  wait->CaptureLayoutF0(g_diplomacyPopupLayoutPosition_006a3020, 0);
  sheet->CaptureLayoutF0(g_diplomacyWarOfferSheetPosition_006a2fe0, 1);
  proposalText->UpdateTextEntrySharedStringAndMaybeNotify(&formattedMessage, 1);
  proposalText->RecenterTextFromMeasuredWidthAndMaybeInvalidate(1);
  RefreshControl();
  ForceRedraw();

  lastNegotiationResponseTag64 = 0;
  while (lastNegotiationResponseTag64 == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
  }
  return lastNegotiationResponseTag64 == static_cast<int>(kControlTagAcce);
}
