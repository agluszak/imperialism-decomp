#include "game/ui_screens/TQueryFloater.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/core/CString.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0043d6d0
TQueryFloater::~TQueryFloater() {}

IMPLEMENT_DYNCREATE(TQueryFloater, TPicture)

// FUNCTION: IMPERIALISM 0x0056e8e0
void TQueryFloater::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  TextStyle style;

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextWithStrListID(0x2757, 1, true);
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);
  titleControl->InstallTextStyle(style, 0);
  titleControl->SetJustification(1, false);

  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6c);
  for (int i = 0; i < 7; ++i) {
    TStaticText* lineControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTex0 + i));
    lineControl->AssertValid();
    lineControl->SetTextWithStrListID(0x2757, static_cast<short>(i + 2), true);
    lineControl->InstallTextStyle(style, 0);
    if (i == 6) {
      lineControl->SetJustification(1, false);
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
    owner->Dismiss(kControlTagOkay, false);
    g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
  } else if (tag == kControlTagBatt) {
    short activeNationId = g_pSimMgr->GetPlayerCountry();
    if (!g_pMapContextActionManager->HasBattlesInvolvingGP(activeNationId)) {
      if (g_pSimMgr->GetEconomicTurn() == 1) {
        g_pSimMgr->GetString(0x273d, 0x1e, &text);
      } else {
        g_pSimMgr->GetString(0x273d, 0x12, &text);
      }
      g_pViewMgr->ModalMessage(text, g_ptQueryFloaterModalMessage, 1, 0);
    } else {
      TWindow* owner = GetWindow();
      owner->Dismiss(kControlTagOkay, false);
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalBattleReport);
    }
  } else if (tag == kControlTagChar) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, false);
    g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalGameStatus);
  } else if (tag == kControlTagClnc) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, false);
  } else if (tag == kControlTagDeal) {
    if (g_pSimMgr->GetEconomicTurn() == 1) {
      g_pSimMgr->GetString(0x2741, 9, &text);
      g_pViewMgr->ModalMessage(text, g_ptQueryFloaterModalMessage, 1, 0);
    } else {
      TWindow* owner = GetWindow();
      owner->Dismiss(kControlTagOkay, false);
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalDealBook);
    }
  } else if (tag == kControlTagNews) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, false);
    if (g_pNewsMgr->perNationStoryLastUsedTick[0] != NULL) {
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalNewspaper);
    } else {
      g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x275e, 6, 2, 0);
    }
  } else if (tag == kControlTagOref) {
    TWindow* owner = GetWindow();
    owner->Dismiss(kControlTagOkay, false);
    g_pHelpMgr->SelectAndActivatePendingEventType1A0A();
  }
}
