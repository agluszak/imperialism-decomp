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
undefined TNominationView::OrphanRetStub_004305c0() {
  return 0;
}

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
void TNominationView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  CString text;
  TUiTextStyleDescriptor style;

  TStaticText* countryControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCoun));
  countryControl->AssertValid();
  countryControl->LoadUiStringAndDispatchViaVslot1C8(0x2733, 0x5f, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0x12, 0x2b6c);
  countryControl->SetTextStyleAndMaybeRefresh(&style, 1);

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->LoadUiStringAndDispatchViaVslot1C8(0x2733, 0x60, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b6c);
  titleControl->SetTextStyleAndMaybeRefresh(&style, 1);

  TStaticText* candidate0Control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCan0));
  candidate0Control->AssertValid();
  TGreatPower* nation0 =
      g_apNationStates[g_pDiplomacyTurnStateManager->selectedSourceNationSlot784];
  nation0->FormatOverlayTerrainLabelText(&text);
  candidate0Control->AssignTextSharedRefIfChangedAndMaybeInvalidate(&text, 1);
  candidate0Control->SetTextStyleAndMaybeRefresh(&style, 1);

  TStaticText* candidate1Control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCan1));
  candidate1Control->AssertValid();
  TGreatPower* nation1 =
      g_apNationStates[g_pDiplomacyTurnStateManager->selectedTargetNationSlot786];
  nation1->FormatOverlayTerrainLabelText(&text);
  candidate1Control->AssignTextSharedRefIfChangedAndMaybeInvalidate(&text, 1);
  candidate1Control->SetTextStyleAndMaybeRefresh(&style, 1);
}

// FUNCTION: IMPERIALISM 0x004fb990
void TNominationView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x7e0);
    return;
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
