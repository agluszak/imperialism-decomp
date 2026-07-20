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

// Turn-event dialog builder handling two event codes. Event 0x8fc (season/turn
// summary): a 'base' TView container (2000x2000) holding a 640x480 'main' TBook panel
// (bitmap 0x8fc) that parents a 'tool' TToolBarCluster (an ' end' TPictureButton, bitmap
// 0x8fd, plus 'seas'/'trea' TDropShadowText labels), a 'Bpot' TToolBarCluster of four
// TUpDownPictureButtons ('tran'/'city'/'trad'/'dipl', bitmaps 0x24ef/0x24ed/0x24eb/0x24e9),
// a 'trb2' TToolBarCluster hosting a 'quer' TPictureButton (bitmap 0x8fe), a 'view'/'page'
// TPageView, two 'lcor'/'rcor' TNoHilitePicture corners (bitmaps 0x939/0x93a), three
// 'ttl1'/'ttl2'/'ttl3' TDropShadowText headers, and a 'crus' TInfoBarText.
// Event 0x942 (tech-history dialog): a 'WIND' TWindow at (151,128) 360x295 owning a 'GOLD'
// TTechHistoryView background, a 'top ' TPicture (bitmap 0x942), a 'titl' TDropShadowText,
// a 'pict' TPicture (bitmap 0x945), a 'scvw' TScrollView, and an 'okay' TUpDownPictureButton
// (bitmap 0x24c2).
// FUNCTION: IMPERIALISM 0x0045e0b0
TView* __cdecl BuildTurnEventDialogResourcesForEvent8FC(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  switch (static_cast<short>(nEventCode)) {
  case 0x8fc: {
    TView* baseContainer = new TView();
    g_pUiResourceContext = baseContainer;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = baseContainer;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(baseContainer);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x7d0;
    size[1] = 0x7d0;
    baseContainer->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    baseContainer->controlTag = static_cast<int>(kControlTagBase);
    baseContainer->controlValue3c = 0;
    baseContainer->SetEnabled(1, 0);
    baseContainer->SetState(0, 0);
    baseContainer->inputGateFlag4c = 1;
    baseContainer->childHitTestFlag4d = 1;
    g_pUiResourceContext = 0;

    TBook* mainBook = new TBook();
    g_pUiResourceContext = mainBook;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = mainBook;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(mainBook);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x280;
    size[1] = 0x1e0;
    mainBook->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    mainBook->controlTag = static_cast<int>(kControlTagMain);
    mainBook->controlValue3c = 0;
    mainBook->SetEnabled(1, 0);
    mainBook->SetState(0, 0);
    mainBook->inputGateFlag4c = 1;
    mainBook->childHitTestFlag4d = 1;
    delete mainBook->stylePayload48;
    mainBook->stylePayload48 = static_cast<TUiStyleBytes*>(operator new(8));
    if (mainBook->stylePayload48 != 0) {
      mainBook->stylePayload48->Reset();
    }
    mainBook->stylePayload48->styleWord = 0;
    mainBook->stylePayload48->packedColor = 0xffffff;
    {
      mainBook->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      mainBook->contentInsets68.left = zeroRect.left;
      mainBook->contentInsets68.top = zeroRect.top;
      mainBook->contentInsets68.right = zeroRect.right;
      mainBook->contentInsets68.bottom = zeroRect.bottom;
      mainBook->SetPictureResourceIdAndRefresh(0x8fc, 0);
    }
    g_pUiResourceContext = 0;

    TToolBarCluster* toolbar = new TToolBarCluster();
    g_pUiResourceContext = toolbar;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = toolbar;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(toolbar);
    offset[0] = 7;
    offset[1] = 6;
    size[0] = 0xe1;
    size[1] = 0x54;
    toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    toolbar->controlTag = static_cast<int>(kControlTagTool);
    toolbar->controlValue3c = 0;
    toolbar->SetEnabled(1, 0);
    toolbar->SetState(0, 0);
    toolbar->inputGateFlag4c = 1;
    toolbar->childHitTestFlag4d = 1;
    {
      toolbar->frameStyle60 = 5;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      toolbar->contentInsets68.left = zeroRect.left;
      toolbar->contentInsets68.top = zeroRect.top;
      toolbar->contentInsets68.right = zeroRect.right;
      toolbar->contentInsets68.bottom = zeroRect.bottom;
      toolbar->field84 = 0x20202020;
    }
    g_pUiResourceContext = 0;

    TPictureButton* endButton = new TPictureButton();
    g_pUiResourceContext = endButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = endButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(endButton);
    offset[0] = 1;
    offset[1] = 0x20;
    size[0] = 0x1e;
    size[1] = 0x32;
    endButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    endButton->controlTag = static_cast<int>(kControlTagEnd);
    endButton->controlValue3c = 0;
    endButton->SetEnabled(0, 0);
    endButton->SetState(1, 0);
    endButton->inputGateFlag4c = 1;
    endButton->childHitTestFlag4d = 1;
    {
      endButton->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      endButton->contentInsets68.left = zeroRect.left;
      endButton->contentInsets68.top = zeroRect.top;
      endButton->contentInsets68.right = zeroRect.right;
      endButton->contentInsets68.bottom = zeroRect.bottom;
      endButton->SetPictureResourceIdAndRefresh(0x8fd, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* seasonLabel = new TDropShadowText();
    g_pUiResourceContext = seasonLabel;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = seasonLabel;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(seasonLabel);
    offset[0] = 0x2c;
    offset[1] = 4;
    size[0] = 0x5e;
    size[1] = 0x11;
    seasonLabel->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    seasonLabel->controlTag = static_cast<int>(kControlTagSeas);
    seasonLabel->controlValue3c = 0;
    seasonLabel->SetEnabled(1, 0);
    seasonLabel->SetState(0, 0);
    seasonLabel->inputGateFlag4c = 1;
    seasonLabel->childHitTestFlag4d = 1;
    {
      seasonLabel->frameStyle60 = 0xd;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      seasonLabel->contentInsets68.left = zeroRect.left;
      seasonLabel->contentInsets68.top = zeroRect.top;
      seasonLabel->contentInsets68.right = zeroRect.right;
      seasonLabel->contentInsets68.bottom = zeroRect.bottom;
      BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* treasuryLabel = new TDropShadowText();
    g_pUiResourceContext = treasuryLabel;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = treasuryLabel;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(treasuryLabel);
    offset[0] = 0x8d;
    offset[1] = 4;
    size[0] = 0x4b;
    size[1] = 0x11;
    treasuryLabel->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    treasuryLabel->controlTag = static_cast<int>(kControlTagTrea);
    treasuryLabel->controlValue3c = 0;
    treasuryLabel->SetEnabled(1, 0);
    treasuryLabel->SetState(0, 0);
    treasuryLabel->inputGateFlag4c = 1;
    treasuryLabel->childHitTestFlag4d = 1;
    {
      treasuryLabel->frameStyle60 = 0xd;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      treasuryLabel->contentInsets68.left = zeroRect.left;
      treasuryLabel->contentInsets68.top = zeroRect.top;
      treasuryLabel->contentInsets68.right = zeroRect.right;
      treasuryLabel->contentInsets68.bottom = zeroRect.bottom;
      BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();

    TToolBarCluster* potToolbar = new TToolBarCluster();
    g_pUiResourceContext = potToolbar;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = potToolbar;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(potToolbar);
    offset[0] = 0x10b;
    offset[1] = 5;
    size[0] = 0x69;
    size[1] = 0x1a;
    potToolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    potToolbar->controlTag = static_cast<int>(kControlTagBpot);
    potToolbar->controlValue3c = 0;
    potToolbar->SetEnabled(1, 0);
    potToolbar->SetState(0, 0);
    potToolbar->inputGateFlag4c = 1;
    potToolbar->childHitTestFlag4d = 1;
    {
      potToolbar->frameStyle60 = 5;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      potToolbar->contentInsets68.left = zeroRect.left;
      potToolbar->contentInsets68.top = zeroRect.top;
      potToolbar->contentInsets68.right = zeroRect.right;
      potToolbar->contentInsets68.bottom = zeroRect.bottom;
      potToolbar->field84 = 0x20202020;
    }
    g_pUiResourceContext = 0;

    TUpDownPictureButton* transportButton = new TUpDownPictureButton();
    g_pUiResourceContext = transportButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = transportButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(transportButton);
    offset[0] = 3;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    transportButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    transportButton->controlTag = static_cast<int>(kControlTagTran);
    transportButton->controlValue3c = 0;
    transportButton->SetEnabled(1, 0);
    transportButton->SetState(1, 0);
    transportButton->inputGateFlag4c = 1;
    transportButton->childHitTestFlag4d = 1;
    {
      transportButton->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      transportButton->contentInsets68.left = zeroRect.left;
      transportButton->contentInsets68.top = zeroRect.top;
      transportButton->contentInsets68.right = zeroRect.right;
      transportButton->contentInsets68.bottom = zeroRect.bottom;
      transportButton->SetPictureResourceIdAndRefresh(0x24ef, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TUpDownPictureButton* cityButton = new TUpDownPictureButton();
    g_pUiResourceContext = cityButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = cityButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(cityButton);
    offset[0] = 0x1f;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    cityButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    cityButton->controlTag = static_cast<int>(kControlTagCity);
    cityButton->controlValue3c = 0;
    cityButton->SetEnabled(1, 0);
    cityButton->SetState(1, 0);
    cityButton->inputGateFlag4c = 1;
    cityButton->childHitTestFlag4d = 1;
    {
      cityButton->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      cityButton->contentInsets68.left = zeroRect.left;
      cityButton->contentInsets68.top = zeroRect.top;
      cityButton->contentInsets68.right = zeroRect.right;
      cityButton->contentInsets68.bottom = zeroRect.bottom;
      cityButton->SetPictureResourceIdAndRefresh(0x24ed, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TUpDownPictureButton* tradeButton = new TUpDownPictureButton();
    g_pUiResourceContext = tradeButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = tradeButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(tradeButton);
    offset[0] = 0x3b;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    tradeButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    tradeButton->controlTag = static_cast<int>(kControlTagTrad);
    tradeButton->controlValue3c = 0;
    tradeButton->SetEnabled(1, 0);
    tradeButton->SetState(1, 0);
    tradeButton->inputGateFlag4c = 1;
    tradeButton->childHitTestFlag4d = 1;
    {
      tradeButton->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      tradeButton->contentInsets68.left = zeroRect.left;
      tradeButton->contentInsets68.top = zeroRect.top;
      tradeButton->contentInsets68.right = zeroRect.right;
      tradeButton->contentInsets68.bottom = zeroRect.bottom;
      tradeButton->SetPictureResourceIdAndRefresh(0x24eb, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TUpDownPictureButton* diplomacyButton = new TUpDownPictureButton();
    g_pUiResourceContext = diplomacyButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = diplomacyButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(diplomacyButton);
    offset[0] = 0x58;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    diplomacyButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    diplomacyButton->controlTag = static_cast<int>(kControlTagDipl);
    diplomacyButton->controlValue3c = 0;
    diplomacyButton->SetEnabled(1, 0);
    diplomacyButton->SetState(1, 0);
    diplomacyButton->inputGateFlag4c = 1;
    diplomacyButton->childHitTestFlag4d = 1;
    {
      diplomacyButton->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      diplomacyButton->contentInsets68.left = zeroRect.left;
      diplomacyButton->contentInsets68.top = zeroRect.top;
      diplomacyButton->contentInsets68.right = zeroRect.right;
      diplomacyButton->contentInsets68.bottom = zeroRect.bottom;
      diplomacyButton->SetPictureResourceIdAndRefresh(0x24e9, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();

    TToolBarCluster* trb2Toolbar = new TToolBarCluster();
    g_pUiResourceContext = trb2Toolbar;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = trb2Toolbar;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(trb2Toolbar);
    offset[0] = 0x258;
    offset[1] = 0x1f;
    size[0] = 0x1e;
    size[1] = 0x30;
    trb2Toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    trb2Toolbar->controlTag = static_cast<int>(kControlTagTbr2);
    trb2Toolbar->controlValue3c = 0;
    trb2Toolbar->SetEnabled(1, 0);
    trb2Toolbar->SetState(0, 0);
    trb2Toolbar->inputGateFlag4c = 1;
    trb2Toolbar->childHitTestFlag4d = 1;
    {
      trb2Toolbar->frameStyle60 = 5;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      trb2Toolbar->contentInsets68.left = zeroRect.left;
      trb2Toolbar->contentInsets68.top = zeroRect.top;
      trb2Toolbar->contentInsets68.right = zeroRect.right;
      trb2Toolbar->contentInsets68.bottom = zeroRect.bottom;
      trb2Toolbar->field84 = 0x20202020;
    }
    g_pUiResourceContext = 0;

    TPictureButton* queryButton = new TPictureButton();
    g_pUiResourceContext = queryButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = queryButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(queryButton);
    offset[0] = 8;
    offset[1] = 9;
    size[0] = 0x16;
    size[1] = 0x26;
    queryButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    queryButton->controlTag = static_cast<int>(kControlTagQuer);
    queryButton->controlValue3c = 0;
    queryButton->SetEnabled(0, 0);
    queryButton->SetState(1, 0);
    queryButton->inputGateFlag4c = 1;
    queryButton->childHitTestFlag4d = 1;
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    queryButton->SetPictureResourceIdAndRefresh(0x8fe, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();

    TTechStorePage* pageView = new TTechStorePage();
    RegisterUiResourceEntry(0x76696577, 0x70616765, pageView, 0x26, 0x40, 0x232, 0x17a, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TNoHilitePicture* leftCorner = new TNoHilitePicture();
    RegisterUiResourceEntry(kControlTagPict, 0x6c636f72, leftCorner, 0x11, 0x1bd, 0x20, 0x1e, 1, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    leftCorner->SetPictureResourceIdAndRefresh(0x939, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TNoHilitePicture* rightCorner = new TNoHilitePicture();
    RegisterUiResourceEntry(kControlTagPict, 0x72636f72, rightCorner, 0x24e, 0x1bd, 0x20, 0x1e, 1,
                            1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    rightCorner->SetPictureResourceIdAndRefresh(0x93a, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* titleText1 = new TDropShadowText();
    RegisterUiResourceEntry(0x73746174, 0x74746c31, titleText1, 0x43, 0x28, 0x80, 0x10, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* titleText2 = new TDropShadowText();
    RegisterUiResourceEntry(0x73746174, 0x74746c32, titleText2, 0xf0, 0x28, 0x80, 0x10, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* titleText3 = new TDropShadowText();
    RegisterUiResourceEntry(0x73746174, 0x74746c33, titleText3, 0x188, 0x28, 0x80, 0x10, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TInfoBarText* cursorInfoText = new TInfoBarText();
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorInfoText, 0x182, 5, 0xc9, 0x1e,
                            0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    g_pUiResourceContext = 0;
  } break;
  case 0x942: {
    TWindow* window = new TWindow();
    g_pUiResourceContext = window;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = window;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(window);
    offset[0] = 0x97;
    offset[1] = 0x80;
    size[0] = 0x168;
    size[1] = 0x127;
    window->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    window->controlTag = static_cast<int>(kControlTagWind);
    window->controlValue3c = 0;
    window->SetEnabled(1, 0);
    window->SetState(1, 0);
    window->inputGateFlag4c = 1;
    window->childHitTestFlag4d = 1;
    window->topmostFlag70 = 0;
    window->flag6f = 1;
    window->flag6e = 1;
    window->useCaptionedFrameFlag6d = 0;
    window->flag6c = 0;
    window->flag71 = 1;
    window->field9c = 8;
    window->windowStyleType = 2;
    TDialogBehavior* behavior = window->GetEmbeddedDialogBehavior();
    behavior->SetFlag0C(1);
    window->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);
    g_pUiResourceContext = 0;

    TTechHistoryView* goldView = new TTechHistoryView();
    g_pUiResourceContext = goldView;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = goldView;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(goldView);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x168;
    size[1] = 0x127;
    goldView->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    goldView->controlTag = static_cast<int>(kControlTagGold);
    goldView->controlValue3c = 0;
    goldView->SetEnabled(1, 0);
    goldView->SetState(0, 0);
    goldView->inputGateFlag4c = 1;
    goldView->childHitTestFlag4d = 1;
    g_pUiResourceContext = 0;

    TPicture* topPicture = new TPicture();
    g_pUiResourceContext = topPicture;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = topPicture;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(topPicture);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x168;
    size[1] = 0x127;
    topPicture->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    topPicture->controlTag = static_cast<int>(kControlTagTop);
    topPicture->controlValue3c = 0;
    topPicture->SetEnabled(1, 0);
    topPicture->SetState(0, 0);
    topPicture->inputGateFlag4c = 1;
    topPicture->childHitTestFlag4d = 1;
    {
      topPicture->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      topPicture->contentInsets68.left = zeroRect.left;
      topPicture->contentInsets68.top = zeroRect.top;
      topPicture->contentInsets68.right = zeroRect.right;
      topPicture->contentInsets68.bottom = zeroRect.bottom;
      topPicture->SetPictureResourceIdAndRefresh(0x942, 0);
    }
    g_pUiResourceContext = 0;

    TDropShadowText* titleText = new TDropShadowText();
    g_pUiResourceContext = titleText;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = titleText;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(titleText);
    offset[0] = 0x51;
    offset[1] = 0x13;
    size[0] = 0x108;
    size[1] = 0x20;
    titleText->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    titleText->controlTag = static_cast<int>(kControlTagTitl);
    titleText->controlValue3c = 0;
    titleText->SetEnabled(1, 0);
    titleText->SetState(0, 0);
    titleText->inputGateFlag4c = 1;
    titleText->childHitTestFlag4d = 1;
    {
      titleText->frameStyle60 = 0xd;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      titleText->contentInsets68.left = zeroRect.left;
      titleText->contentInsets68.top = zeroRect.top;
      titleText->contentInsets68.right = zeroRect.right;
      titleText->contentInsets68.bottom = zeroRect.bottom;
      BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TPicture* patchPicture = new TPicture();
    g_pUiResourceContext = patchPicture;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = patchPicture;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(patchPicture);
    offset[0] = 0xa;
    offset[1] = 0xa;
    size[0] = 0x3c;
    size[1] = 0x3c;
    patchPicture->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    patchPicture->controlTag = static_cast<int>(kControlTagPict);
    patchPicture->controlValue3c = 0;
    patchPicture->SetEnabled(1, 0);
    patchPicture->SetState(0, 0);
    patchPicture->inputGateFlag4c = 1;
    patchPicture->childHitTestFlag4d = 1;
    {
      patchPicture->frameStyle60 = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      patchPicture->contentInsets68.left = zeroRect.left;
      patchPicture->contentInsets68.top = zeroRect.top;
      patchPicture->contentInsets68.right = zeroRect.right;
      patchPicture->contentInsets68.bottom = zeroRect.bottom;
      patchPicture->SetPictureResourceIdAndRefresh(0x945, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TTechHistoryView* scrollView = new TTechHistoryView();
    g_pUiResourceContext = scrollView;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = scrollView;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(scrollView);
    offset[0] = 9;
    offset[1] = 0x4c;
    size[0] = 0x156;
    size[1] = 0xaf;
    scrollView->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    scrollView->controlTag = static_cast<int>(kControlTagScvw);
    scrollView->controlValue3c = 0;
    scrollView->SetEnabled(1, 0);
    scrollView->SetState(0, 0);
    scrollView->inputGateFlag4c = 1;
    scrollView->childHitTestFlag4d = 1;
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TUpDownPictureButton* okayButton = new TUpDownPictureButton();
    g_pUiResourceContext = okayButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = okayButton;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(okayButton);
    offset[0] = 0x119;
    offset[1] = 0x104;
    size[0] = 0x3d;
    size[1] = 0x18;
    okayButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    okayButton->controlTag = static_cast<int>(kControlTagOkay);
    okayButton->controlValue3c = 0;
    okayButton->SetEnabled(1, 0);
    okayButton->SetState(1, 0);
    okayButton->inputGateFlag4c = 1;
    okayButton->childHitTestFlag4d = 1;
    {
      okayButton->frameStyle60 = 0x22;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      okayButton->contentInsets68.left = zeroRect.left;
      okayButton->contentInsets68.top = zeroRect.top;
      okayButton->contentInsets68.right = zeroRect.right;
      okayButton->contentInsets68.bottom = zeroRect.bottom;
      okayButton->SetPictureResourceIdAndRefresh(0x24c2, 0);
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
  } break;
  default:
    return 0;
  }

  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
