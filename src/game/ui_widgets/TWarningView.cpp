#include "game/ui_widgets/TWarningView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00592860
// TWarningView::CreateObject
// SYNTHETIC: IMPERIALISM 0x005928e0
// TWarningView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWarningView, TPicture)

// FUNCTION: IMPERIALISM 0x00592900
TWarningView::TWarningView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00592930
// TWarningView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00592960
TWarningView::~TWarningView() {}

// FUNCTION: IMPERIALISM 0x00592980
void TWarningView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x22) {
    unsigned int controlTag = sourceHandler->controlTag;
    switch (controlTag) {
    case kControlTagPic1:
      g_pSimMgr->EnterOptionalPhase(0x68);
      break;
    case kControlTagPic1 + 1:
      g_pSimMgr->EnterOptionalPhase(0x67);
      break;
    case kControlTagPic1 + 2:
      g_pSimMgr->EnterOptionalPhase(0x6a);
      break;
    case kControlTagPic1 + 3:
      g_pSimMgr->EnterOptionalPhase(0x69);
      break;
    case kControlTagPic5:
      g_pSimMgr->EnterOptionalPhase(5);
      break;
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00592a70
void TWarningView::DoPostCreate(int arg) {
  (void)arg;
  const unsigned int kControlTagMsg1 = IMPERIALISM_FOURCC('m', 's', 'g', '1');
  const unsigned int kControlTagMsg2 = IMPERIALISM_FOURCC('m', 's', 'g', '2');
  const unsigned int kControlTagMsg3 = IMPERIALISM_FOURCC('m', 's', 'g', '3');
  const unsigned int kControlTagMsg4 = IMPERIALISM_FOURCC('m', 's', 'g', '4');
  const unsigned int kControlTagMsg5 = IMPERIALISM_FOURCC('m', 's', 'g', '5');

  TextStyle style;
  style.textColor = 0;
  TView* panel = GetWindow();
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b67);

  TStaticText* title = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagTitl));
  title->AssertValid();
  title->InstallTextStyle(style, 0);
  {
    CString titleText("Ministers request orders:");
    title->SetTextAndMaybeRefresh(&titleText, 0);
  }
  title->SetTextAlignmentAndMaybeRefresh(1, 0);
  title->Show(1, 0);

  TStaticText* endTurn = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg5));
  endTurn->AssertValid();
  endTurn->InstallTextStyle(style, 0);
  {
    CString endTurnText("End Turn Now");
    endTurn->SetTextAndMaybeRefresh(&endTurnText, 0);
  }
  endTurn->Show(1, 0);

  TView* endTurnPicture = panel->ResolveControlByTag(kControlTagPic5);
  endTurnPicture->AssertValid();
  endTurnPicture->ViewEnable(1, 0);
  endTurnPicture->Show(1, 0);

  unsigned int pendingAlerts = g_pSimMgr->alertsPendingFlag38;
  if ((pendingAlerts & 1) != 0) {
    TStaticText* diplomacy = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg1));
    diplomacy->AssertValid();
    diplomacy->InstallTextStyle(style, 0);
    {
      CString diplomacyText("Diplomacy");
      diplomacy->SetTextAndMaybeRefresh(&diplomacyText, 0);
    }
    diplomacy->Show(1, 0);
    TView* picture = panel->ResolveControlByTag(kControlTagPic1);
    picture->AssertValid();
    picture->ViewEnable(1, 0);
    picture->Show(1, 0);
  }

  if ((pendingAlerts & 0x1000) != 0) {
    TStaticText* transport = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg4));
    transport->AssertValid();
    transport->InstallTextStyle(style, 0);
    {
      CString transportText("Transport");
      transport->SetTextAndMaybeRefresh(&transportText, 0);
    }
    transport->Show(1, 0);
    TView* picture = panel->ResolveControlByTag(kControlTagPic1 + 3);
    picture->AssertValid();
    picture->ViewEnable(1, 0);
    picture->Show(1, 0);
  }

  if ((pendingAlerts & 0x100) != 0) {
    TStaticText* trade = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg2));
    trade->AssertValid();
    trade->InstallTextStyle(style, 0);
    {
      CString tradeText("Trade");
      trade->SetTextAndMaybeRefresh(&tradeText, 0);
    }
    trade->Show(1, 0);
    TView* picture = panel->ResolveControlByTag(kControlTagPic1 + 1);
    picture->AssertValid();
    picture->ViewEnable(1, 0);
    picture->Show(1, 0);
  }

  if ((pendingAlerts & 0x10) != 0) {
    TStaticText* industry = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg3));
    industry->AssertValid();
    industry->InstallTextStyle(style, 0);
    {
      CString industryText("Industry");
      industry->SetTextAndMaybeRefresh(&industryText, 0);
    }
    industry->Show(1, 0);
    TView* picture = panel->ResolveControlByTag(kControlTagPic1 + 2);
    picture->AssertValid();
    picture->ViewEnable(1, 0);
    picture->Show(1, 0);
  }
}
