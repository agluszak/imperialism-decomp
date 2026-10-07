#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/diplomacy_ui/TNominationView.h"

#include "game/ui_core/TApplication.h"
#include "game/ui_core/TControl.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TStaticText.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004305c0
void TNominationView::Hilite() {}

// FUNCTION: IMPERIALISM 0x00430610
TNominationView::~TNominationView() {}

IMPLEMENT_DYNCREATE(TNominationView, TPicture)

// FUNCTION: IMPERIALISM 0x004fb780
void TNominationView::DoPostCreate(int arg) {
  CString text;
  TextStyle style;

  TStaticText* countryControl = static_cast<TStaticText*>(FindSubView(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->SetTextWithStrListID(0x2733, 0x5f, true);
  BuildUiTextStyleDescriptor(&style, 0, 0x12, 0x2b6c);
  countryControl->InstallTextStyle(style, 1);

  TStaticText* titleControl = static_cast<TStaticText*>(FindSubView(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextWithStrListID(0x2733, 0x60, true);
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b6c);
  titleControl->InstallTextStyle(style, 1);

  TStaticText* candidate0Control = static_cast<TStaticText*>(FindSubView(kControlTagCan0));
  candidate0Control->AssertValid();
  TGreatPower* nation0 =
      g_apNationStates[g_pDiplomacyTurnStateManager->congressLeadership.chairmanNationSlot];
  nation0->FormatOverlayTerrainLabelText(&text);
  candidate0Control->SetTextAndMaybeRefresh(&text, true);
  candidate0Control->InstallTextStyle(style, 1);

  TStaticText* candidate1Control = static_cast<TStaticText*>(FindSubView(kControlTagCan1));
  candidate1Control->AssertValid();
  TGreatPower* nation1 =
      g_apNationStates[g_pDiplomacyTurnStateManager->congressLeadership.counterpartNationSlot];
  nation1->FormatOverlayTerrainLabelText(&text);
  candidate1Control->SetTextAndMaybeRefresh(&text, true);
  candidate1Control->InstallTextStyle(style, 1);
}

// FUNCTION: IMPERIALISM 0x004fb990
void TNominationView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    g_pAmbitApplication->PostTurnEventCodeMessage(
        EncodeTurnEventCode(kTurnEventCouncilOfGovernors));
    return;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
