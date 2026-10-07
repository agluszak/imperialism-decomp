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

IMPLEMENT_DYNCREATE(TWarningView, TPicture)

// FUNCTION: IMPERIALISM 0x00592900
TWarningView::TWarningView() : TPicture() {}

// FUNCTION: IMPERIALISM 0x00592960
TWarningView::~TWarningView() {}

// FUNCTION: IMPERIALISM 0x00592980
void TWarningView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x22) {
    unsigned int controlTag = sourceHandler->controlTag;
    switch (controlTag) {
    case kControlTagPic1:
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalDiplomacyMap);
      break;
    case kControlTagPic1 + 1:
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalTradeOverview);
      break;
    case kControlTagPic1 + 2:
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalCityScreen);
      break;
    case kControlTagPic1 + 3:
      g_pSimMgr->EnterOptionalPhase(kGamePhaseOptionalTransport);
      break;
    case kControlTagPic5:
      g_pSimMgr->EnterOptionalPhase(kGamePhaseEndTurn);
      break;
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00592a70
void TWarningView::DoPostCreate(int arg) {
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
    title->SetTextAndMaybeRefresh(&titleText, false);
  }
  title->SetJustification(1, false);
  title->Show(1, 0);

  TStaticText* endTurn = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg5));
  endTurn->AssertValid();
  endTurn->InstallTextStyle(style, 0);
  {
    CString endTurnText("End Turn Now");
    endTurn->SetTextAndMaybeRefresh(&endTurnText, false);
  }
  endTurn->Show(1, 0);

  TView* endTurnPicture = panel->ResolveControlByTag(kControlTagPic5);
  endTurnPicture->AssertValid();
  endTurnPicture->ViewEnable(1, 0);
  endTurnPicture->Show(1, 0);

  unsigned int pendingAlerts = g_pSimMgr->alertsPendingFlag;
  if ((pendingAlerts & 1) != 0) {
    TStaticText* diplomacy = static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagMsg1));
    diplomacy->AssertValid();
    diplomacy->InstallTextStyle(style, 0);
    {
      CString diplomacyText("Diplomacy");
      diplomacy->SetTextAndMaybeRefresh(&diplomacyText, false);
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
      transport->SetTextAndMaybeRefresh(&transportText, false);
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
      trade->SetTextAndMaybeRefresh(&tradeText, false);
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
      industry->SetTextAndMaybeRefresh(&industryText, false);
    }
    industry->Show(1, 0);
    TView* picture = panel->ResolveControlByTag(kControlTagPic1 + 2);
    picture->AssertValid();
    picture->ViewEnable(1, 0);
    picture->Show(1, 0);
  }
}
