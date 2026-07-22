#include "game/TAmbitApplication.h"
#include "game/TNominationView.h"

#include "game/TApplication.h"
#include "game/TControl.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TStaticText.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004305c0
void TNominationView::Hilite() {}

// SYNTHETIC: IMPERIALISM 0x004305e0
// TNominationView::`scalar deleting destructor'
TNominationView::~TNominationView() {}
// SYNTHETIC: IMPERIALISM 0x004fb6e0
// TNominationView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fb760
// TNominationView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNominationView, TPicture)

TNominationView::TNominationView() {}

// FUNCTION: IMPERIALISM 0x004fb780
void TNominationView::DoPostCreate(int arg) {
  (void)arg;
  CString text;
  TextStyle style;

  TStaticText* countryControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->SetTextFromStringResource(0x2733, 0x5f, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0x12, 0x2b6c);
  countryControl->InstallTextStyle(style, 1);

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextFromStringResource(0x2733, 0x60, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b6c);
  titleControl->InstallTextStyle(style, 1);

  TStaticText* candidate0Control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCan0));
  candidate0Control->AssertValid();
  TGreatPower* nation0 =
      g_apNationStates[g_pDiplomacyTurnStateManager->selectedSourceNationSlot784];
  nation0->FormatOverlayTerrainLabelText(&text);
  candidate0Control->SetTextAndMaybeRefresh(&text, 1);
  candidate0Control->InstallTextStyle(style, 1);

  TStaticText* candidate1Control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCan1));
  candidate1Control->AssertValid();
  TGreatPower* nation1 =
      g_apNationStates[g_pDiplomacyTurnStateManager->selectedTargetNationSlot786];
  nation1->FormatOverlayTerrainLabelText(&text);
  candidate1Control->SetTextAndMaybeRefresh(&text, 1);
  candidate1Control->InstallTextStyle(style, 1);
}

// FUNCTION: IMPERIALISM 0x004fb990
void TNominationView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventCouncilOfGovernors));
    return;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
