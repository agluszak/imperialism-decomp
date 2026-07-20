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

// Season-report screen for event code 0x898: a 2000x2000 'base' container holding a
// full-screen 640x480 'main' picture (bitmap 0x898), a 'text' body block bound to
// placeholder sample text, and a 'tool' toolbar cluster hosting an ' end' picture
// button (bitmap 0x8b4) plus 'seas'/'trea' drop-shadow labels (placeholder
// "Winter, 1888"/"$55,555"); a 'curs' info-bar text and a 'patc' picture (bitmap 0x8b6)
// hang off the 'main' panel.
// FUNCTION: IMPERIALISM 0x0045d520
TView* __cdecl BuildTurnEventDialogResourcesForEvent898(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  TView* widget;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  if (static_cast<short>(nEventCode) != 0x898) {
    return 0;
  }

  // 'base' container (2000x2000)
  widget = new TView();
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
  size[0] = 0x7d0;
  size[1] = 0x7d0;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagBase);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;

  // 'main' picture (640x480, bitmap 0x898)
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
  size[0] = 0x280;
  size[1] = 0x1e0;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagMain);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  delete widget->stylePayload48;
  widget->stylePayload48 = static_cast<TUiStyleBytes*>(operator new(8));
  if (widget->stylePayload48 != 0) {
    widget->stylePayload48->Reset();
  }
  widget->stylePayload48->styleWord = 0;
  widget->stylePayload48->packedColor = 0xffffff;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x898, 0);
  }

  // 'text' body block
  widget = new TStaticText();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0x131;
  offset[1] = 0x14f;
  size[0] = 0x128;
  size[1] = 0x7a;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagText);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0xd;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    BindUiResourceTextAndStyle(0xc80, 1, g_szUiPlaceholderSampleText_00694A98, 3, 0, 0xc, 0, 1);
  }
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'tool' toolbar cluster
  widget = new TToolBarCluster();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 3;
  offset[1] = 6;
  size[0] = 0xed;
  size[1] = 0x5a;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagTool);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 5;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    static_cast<TCluster*>(g_pUiResourceContext)->field84 = 0x20202020;
  }

  // ' end' picture button
  widget = new TPictureButton();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 5;
  offset[1] = 0x20;
  size[0] = 0x1f;
  size[1] = 0x33;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagEnd);
  widget->controlValue3c = 0;
  widget->SetEnabled(0, 0);
  widget->SetState(1, 0);
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
    static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x8b4, 0);
  }
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'seas' drop-shadow label
  widget = new TDropShadowText();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0x2c;
  offset[1] = 1;
  size[0] = 0x5e;
  size[1] = 0x11;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagSeas);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0xd;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
  }
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'trea' drop-shadow label
  widget = new TDropShadowText();
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(widget);
  offset[0] = 0x8d;
  offset[1] = 1;
  size[0] = 0x4b;
  size[1] = 0x11;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  widget->controlTag = static_cast<int>(kControlTagTrea);
  widget->controlValue3c = 0;
  widget->SetEnabled(1, 0);
  widget->SetState(0, 0);
  widget->inputGateFlag4c = 1;
  widget->childHitTestFlag4d = 1;
  {
    static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = 0xd;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.left = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.top = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.right = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->contentInsets68.bottom = zeroRect.bottom;
    BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
  }
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();

  // 'curs' info-bar text
  widget = new TInfoBarText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, widget, 0xf7, 7, 0x155, 0x11, 0, 1,
                          kControlTagMain, 0);
  SetUiResourceStateFlags(1, 0);
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  // 'patc' picture
  widget = new TPicture();
  RegisterUiResourceEntry(kControlTagPict, kControlTagPatc, widget, 0x248, 0x23, 0x34, 0x48, 0, 1,
                          kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
  static_cast<TPicture*>(widget)->SetPictureResourceIdAndRefresh(0x8b6, 0);
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
