#include "game/turn_event_dialog_factory.h"

#include "game/TBook.h"
#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TDropShadowNumberText.h"
#include "game/TDropShadowText.h"
#include "game/TDlgWindow.h"
#include "game/TEditText.h"
#include "game/TGWorldPartView.h"
#include "game/TMapPreviewView.h"
#include "game/TRadioText.h"
#include "game/TRadioTextCluster.h"
#include "game/TSetupRandomMapPicture.h"
#include "game/TGameSetupPicture.h"
#include "game/TMyNumberText.h"
#include "game/TNoHilitePicture.h"
#include "game/TPageView.h"
#include "game/TScrollView.h"
#include "game/TSidewaysArrow.h"
#include "game/TSliderPicture.h"
#include "game/TTechHistoryView.h"
#include "game/TTechStorePage.h"
#include "game/TGameWindow.h"
#include "game/TInfoBarText.h"
#include "game/TPicture.h"
#include "game/TPictureButton.h"
#include "game/TStaticText.h"
#include "game/TToolBarCluster.h"
#include "game/TTradeCluster.h"
#include "game/TTradeOrderPicture.h"
#include "game/TTradeScreenPicture.h"
#include "game/TTraderAmtBar.h"
#include "game/TMovieView.h"
#include "game/TUpDownPictureButton.h"
#include "game/TView.h"
#include "game/TWindow.h"
#include "game/TFloatWindow.h"
#include "game/TUniversityView.h"
#include "game/TArmyInfoView.h"
#include "game/TArmyPlacard.h"
#include "game/TArmyToolbar.h"
#include "game/TCivDescription.h"
#include "game/TCivReport.h"
#include "game/TCivToolbar.h"
#include "game/TColorKeyPicture.h"
#include "game/TCombatReportView.h"
#include "game/TCzechBox.h"
#include "game/TGamePreferencesPicture.h"
#include "game/TLoadSavePicture.h"
#include "game/TMadnessButton.h"
#include "game/TNoHiliteText.h"
#include "game/TTwoPicSlider.h"
#include "game/TEngineerDialog.h"
#include "game/TGarrisonView.h"
#include "game/TMapDialog.h"
#include "game/TMapUberPicture.h"
#include "game/TNavyRoster.h"
#include "game/TNavyToolbarCluster.h"
#include "game/TNumberText.h"
#include "game/TNumberedArrowButton.h"
#include "game/TOceanDialog.h"
#include "game/TPageCorner.h"
#include "game/TRadioPictureButton.h"
#include "game/TShipFractionCluster.h"
#include "game/TShipPlacard.h"
#include "game/TCitySiteView.h"
#include "game/TClickZone.h"
#include "game/TGameScorePicture.h"
#include "game/TGameSetupMultiplayerPicture.h"
#include "game/THighScoresPicture.h"
#include "game/TMyStaticText.h"
#include "game/TNetSelectPicture.h"
#include "game/TPlaceCityDialog.h"
#include "game/TScenarioChooser.h"
#include "game/TSpecialQuitPicture.h"
#include "game/TTEView.h"
#include "game/TTextList.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_resource_builder.h"

#include "game/turn_event_dialog_builder_detail.h"

// Diplomatic-message screen for event code 0x2508: a 'WIND' host window at (100,80)
// size 390x282, a full-panel 'GOLD' background picture (bitmap 0x252a) that parents the
// remaining controls, an 'okay' confirm button (bitmap 0x24c2), a 'rewa' reward picture
// (bitmap 0x2508 — same id as the event code), a 'coat' coat-of-arms picture (bitmap
// 0x251c), and an 'info' TDeluxeText block.
// FUNCTION: IMPERIALISM 0x0044a810
TView* __cdecl BuildTurnEventDialogResources_2508(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  TView* widget;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  if (static_cast<short>(nEventCode) != 0x2508) {
    return 0;
  }

  // 'WIND' host window
  widget = new TWindow();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0x64;
  offset[1] = 0x50;
  size[0] = 0x186;
  size[1] = 0x11a;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagWind);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(1, 0);
  g_pUiResourceContext->inputGateFlag4c = 1;
  g_pUiResourceContext->childHitTestFlag4d = 1;
  static_cast<TWindow*>(g_pUiResourceContext)->topmostFlag70 = 0;
  static_cast<TWindow*>(g_pUiResourceContext)->flag6f = 1;
  static_cast<TWindow*>(g_pUiResourceContext)->flag6e = 1;
  static_cast<TWindow*>(g_pUiResourceContext)->useCaptionedFrameFlag6d = 0;
  static_cast<TWindow*>(g_pUiResourceContext)->flag6c = 0;
  static_cast<TWindow*>(g_pUiResourceContext)->flag71 = 1;
  static_cast<TWindow*>(g_pUiResourceContext)->field9c = 8;
  static_cast<TWindow*>(g_pUiResourceContext)->windowStyleType = 2;
  static_cast<TWindow*>(g_pUiResourceContext)->GetEmbeddedDialogBehavior()->SetFlag0C(1);
  static_cast<TWindow*>(g_pUiResourceContext)
      ->GetEmbeddedDialogBehavior()
      ->SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);
  g_pUiResourceContext = 0;

  // 'GOLD' background picture
  widget = new TPicture();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0;
  offset[1] = 0;
  size[0] = 0x186;
  size[1] = 0x11a;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagGold);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x252a, 0);
  }
  g_pUiResourceContext = 0;

  // 'okay' confirm button
  widget = new TUpDownPictureButton();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0x136;
  offset[1] = 0xf8;
  size[0] = 0x3d;
  size[1] = 0x17;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagOkay);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(1, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0x22;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24c2, 0);
  }
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'rewa' reward picture
  widget = new TPicture();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0x70;
  offset[1] = 0x12;
  size[0] = 0xa7;
  size[1] = 0x6d;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagRewa);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x2508, 0);
  }
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'coat' coat-of-arms picture
  widget = new TPicture();
  RegisterUiResourceEntry(kControlTagPict, kControlTagCoat, widget, 0x127, 0xc, 0x54, 0x7d, 0, 1,
                          kControlTagGold, 0);
  static_cast<TControl*>(g_pUiResourceContext)->inputGateFlag4c = 1;
  static_cast<TControl*>(g_pUiResourceContext)->childHitTestFlag4d = 1;
  SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
  static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x251c, 0);
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'info' deluxe text
  widget = new TDeluxeText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagInfo, widget, 0x11, 0xa0, 0x162, 0x54, 0, 1,
                          kControlTagGold, 0);
  static_cast<TControl*>(g_pUiResourceContext)->inputGateFlag4c = 1;
  static_cast<TControl*>(g_pUiResourceContext)->childHitTestFlag4d = 0;
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
