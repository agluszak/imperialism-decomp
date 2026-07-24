#include "game/ui_screens/TQueryFloater.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/ui_screens/CString.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0043d6a0
// TQueryFloater::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0043d6d0
TQueryFloater::~TQueryFloater() {}
// SYNTHETIC: IMPERIALISM 0x0056e840
// TQueryFloater::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056e8c0
// TQueryFloater::GetRuntimeClass

IMPLEMENT_DYNCREATE(TQueryFloater, TPicture)

// NOOP: verified empty in original 0x0056e876 (no standalone TQueryFloater::TQueryFloater body exists: CreateObject 0x0056e840 inlines this default ctor, calling the TPicture base ctor directly at that site)
TQueryFloater::TQueryFloater() {}

// FUNCTION: IMPERIALISM 0x0056e8e0
void TQueryFloater::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  TextStyle style;

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->GetNextHandler();
  titleControl->SetTextFromStringResource(0x2757, 1, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);
  titleControl->InstallTextStyle(style, 0);
  titleControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6c);
  for (int i = 0; i < 7; ++i) {
    TStaticText* lineControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTex0 + i));
    lineControl->GetNextHandler();
    lineControl->SetTextFromStringResource(0x2757, static_cast<short>(i + 2), 1);
    lineControl->InstallTextStyle(style, 0);
    if (i == 6) {
      lineControl->SetTextAlignmentAndMaybeRefresh(1, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056ea20
void TQueryFloater::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  CString text;
  if (commandId != 0xa) {
    return;
  }
  unsigned int tag = sourceHandler->controlTag;
  if (tag == kControlTagAdvi) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, 0);
    g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
  } else if (tag == kControlTagBatt) {
    short activeNationId = g_pSimMgr->GetActiveNationId();
    if (!g_pMapContextActionManager->ScanMapContextActionEntriesForCodeMatch(activeNationId)) {
      if (g_pSimMgr->GetEconomicTurn() == 1) {
        g_pSimMgr->GetString(0x273d, 0x1e, &text);
      } else {
        g_pSimMgr->GetString(0x273d, 0x12, &text);
      }
      g_pUiRuntimeContext->ModalMessage(text, g_ptQueryFloaterModalMessage, 1, 0);
    } else {
      TWindow* owner = GetWindow();
      owner->Dismiss(kControlTagOkay, 0);
      g_pSimMgr->EnterOptionalPhase(0x65);
    }
  } else if (tag == kControlTagChar) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, 0);
    g_pSimMgr->EnterOptionalPhase(0x6e);
  } else if (tag == kControlTagClnc) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, 0);
  } else if (tag == kControlTagDeal) {
    if (g_pSimMgr->GetEconomicTurn() == 1) {
      g_pSimMgr->GetString(0x2741, 9, &text);
      g_pUiRuntimeContext->ModalMessage(text, g_ptQueryFloaterModalMessage, 1, 0);
    } else {
      TWindow* owner = GetWindow();
      owner->Dismiss(kControlTagOkay, 0);
      g_pSimMgr->EnterOptionalPhase(0x64);
    }
  } else if (tag == kControlTagNews) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, 0);
    if (g_pNewsMgr->perNationStoryLastUsedTick[0] != nullptr) {
      g_pSimMgr->EnterOptionalPhase(0x66);
    } else {
      g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x275e, 6, 2, 0);
    }
  } else if (tag == kControlTagOref) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, 0);
    g_pHelpMgr->SelectAndActivatePendingEventType1A0A();
  }
}
