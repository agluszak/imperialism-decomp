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

// University screen (turn event 0x23fa): a 'WIND' TFloatWindow hosting the
// TUniversityView 'GOLD' panel, recruit paper/level edit fields, and the
// recruitment rows (nmbr/numb number clusters, fix1-fix4 labels). One linear
// build - the original TU predates the compact helper vocabulary, so most
// widgets use the expanded idiom.
// FUNCTION: IMPERIALISM 0x004749a0
TView* __cdecl BuildUniversityDialogShell(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  if (static_cast<short>(nEventCode) != 0x23fa) {
    return 0;
  }

  {
    TFloatWindow* w1 = new TFloatWindow();
    g_pUiResourceContext = w1;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w1;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w1);
    offset[0] = 0x33;
    offset[1] = 0x3d;
    size[0] = 0x172;
    size[1] = 0x19a;
    w1->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w1->controlTag = static_cast<int>(0x57494e44 /* 'WIND' */);
    w1->controlValue3c = 0;
    w1->SetEnabled(1, 0);
    w1->SetState(1, 0);
    w1->inputGateFlag4c = 1;
    w1->childHitTestFlag4d = 1;
    w1->topmostFlag70 = 1;
    w1->flag6f = 1;
    w1->flag6e = 1;
    w1->useCaptionedFrameFlag6d = 1;
    w1->flag6c = 0;
    w1->flag71 = 1;
    w1->field9c = 0x80;
    w1->windowStyleType = 0x1f40;
    TDialogBehavior* behavior = w1->GetEmbeddedDialogBehavior();
    behavior->SetFlag0C(1);
    w1->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(0, 0x20202020, 0x20202020);
    g_pUiResourceContext = 0;
  }
  {
    TUniversityView* w2 = new TUniversityView();
    g_pUiResourceContext = w2;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w2;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w2);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x172;
    size[1] = 0x19a;
    w2->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w2->controlTag = static_cast<int>(0x444c4f47 /* 'DLOG' */);
    w2->controlValue3c = 0;
    w2->SetEnabled(1, 0);
    w2->SetState(0, 0);
    w2->inputGateFlag4c = 1;
    w2->childHitTestFlag4d = 1;
    w2->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w2->contentInsets68.left = layoutRect.left;
    w2->contentInsets68.top = layoutRect.top;
    w2->contentInsets68.right = layoutRect.right;
    w2->contentInsets68.bottom = layoutRect.bottom;
    w2->SetPictureResourceIdAndRefresh(0x26ac, 0);
    g_pUiResourceContext = 0;
  }
  {
    TNumberText* w3 = new TNumberText();
    g_pUiResourceContext = w3;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w3;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w3);
    offset[0] = 0x60;
    offset[1] = 0xe5;
    size[0] = 0x17;
    size[1] = 0x15;
    w3->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w3->controlTag = static_cast<int>(0x61706170 /* 'apap' */);
    w3->controlValue3c = 0;
    w3->SetEnabled(1, 0);
    w3->SetState(0, 0);
    w3->inputGateFlag4c = 1;
    w3->childHitTestFlag4d = 0;
    w3->frameStyle60 = 6;
    CRect layoutRect(3, 3, 3, 3);
    w3->contentInsets68.left = layoutRect.left;
    w3->contentInsets68.top = layoutRect.top;
    w3->contentInsets68.right = layoutRect.right;
    w3->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 0);
    w3->AssertValid();
    w3->field_9c = 0xff;
    w3->AssertValid();
    w3->field_a4 = 0;
    w3->field_a8 = 0xff;
    w3->SetControlValue(0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TNumberText* w4 = new TNumberText();
    g_pUiResourceContext = w4;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w4;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w4);
    offset[0] = 0x60;
    offset[1] = 0xba;
    size[0] = 0x17;
    size[1] = 0x15;
    w4->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w4->controlTag = static_cast<int>(0x63706170 /* 'cpap' */);
    w4->controlValue3c = 0;
    w4->SetEnabled(1, 0);
    w4->SetState(0, 0);
    w4->inputGateFlag4c = 1;
    w4->childHitTestFlag4d = 0;
    w4->frameStyle60 = 6;
    CRect layoutRect(3, 3, 3, 3);
    w4->contentInsets68.left = layoutRect.left;
    w4->contentInsets68.top = layoutRect.top;
    w4->contentInsets68.right = layoutRect.right;
    w4->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 0);
    w4->AssertValid();
    w4->field_9c = 0xff;
    w4->AssertValid();
    w4->field_a4 = 0;
    w4->field_a8 = 0xff;
    w4->SetControlValue(0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w5 = new TStaticText();
    g_pUiResourceContext = w5;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w5;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w5);
    offset[0] = 0x10;
    offset[1] = 0xce;
    size[0] = 0x49;
    size[1] = 0xe;
    w5->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w5->controlTag = static_cast<int>(0x66697831 /* 'fix1' */);
    w5->controlValue3c = 0;
    w5->SetEnabled(1, 0);
    w5->SetState(0, 0);
    w5->inputGateFlag4c = 1;
    w5->childHitTestFlag4d = 1;
    w5->frameStyle60 = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w5->contentInsets68.left = layoutRect.left;
    w5->contentInsets68.top = layoutRect.top;
    w5->contentInsets68.right = layoutRect.right;
    w5->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, 2, g_szUiAvailableColon_006949C8, 3, 0, 9, 0, -2);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w6 = new TStaticText();
    g_pUiResourceContext = w6;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w6;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w6);
    offset[0] = 0x10;
    offset[1] = 0xa2;
    size[0] = 0x49;
    size[1] = 0xe;
    w6->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w6->controlTag = static_cast<int>(0x66697830 /* 'fix0' */);
    w6->controlValue3c = 0;
    w6->SetEnabled(1, 0);
    w6->SetState(0, 0);
    w6->inputGateFlag4c = 1;
    w6->childHitTestFlag4d = 1;
    w6->frameStyle60 = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w6->contentInsets68.left = layoutRect.left;
    w6->contentInsets68.top = layoutRect.top;
    w6->contentInsets68.right = layoutRect.right;
    w6->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, 1, g_szUiCostColon_006949D8, 3, 0, 9, 0, -2);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w7 = new TStaticText();
    g_pUiResourceContext = w7;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w7;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w7);
    offset[0] = 0x3f;
    offset[1] = 0xfe;
    size[0] = 0x24;
    size[1] = 0x1a;
    w7->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w7->controlTag = static_cast<int>(0x66697832 /* 'fix2' */);
    w7->controlValue3c = 0;
    w7->SetEnabled(1, 0);
    w7->SetState(0, 0);
    w7->inputGateFlag4c = 1;
    w7->childHitTestFlag4d = 1;
    CRect layoutRect(0, 0, 0, 0);
    w7->contentInsets68.left = layoutRect.left;
    w7->contentInsets68.top = layoutRect.top;
    w7->contentInsets68.right = layoutRect.right;
    w7->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, 4, g_szUiLevel1_00694B38, 3, 0, 9, 0, -2);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w8 = new TStaticText();
    g_pUiResourceContext = w8;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w8;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w8);
    offset[0] = 0x7b;
    offset[1] = 0xb6;
    size[0] = 0x3e;
    size[1] = 0xd;
    w8->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w8->controlTag = static_cast<int>(0x63617368 /* 'cash' */);
    w8->controlValue3c = 0;
    w8->SetEnabled(1, 0);
    w8->SetState(0, 0);
    w8->inputGateFlag4c = 1;
    w8->childHitTestFlag4d = 1;
    CRect layoutRect(0, 0, 0, 0);
    w8->contentInsets68.left = layoutRect.left;
    w8->contentInsets68.top = layoutRect.top;
    w8->contentInsets68.right = layoutRect.right;
    w8->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, 3, g_szUiThousandDollars_00694B30, 3, 0, 9, 0, -1);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w9 = new TStaticText();
    g_pUiResourceContext = w9;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w9;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w9);
    offset[0] = 0xf;
    offset[1] = 0x52;
    size[0] = 0x6e;
    size[1] = 0x4d;
    w9->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w9->controlTag = static_cast<int>(0x64657363 /* 'desc' */);
    w9->controlValue3c = 0;
    w9->SetEnabled(1, 0);
    w9->SetState(0, 0);
    w9->inputGateFlag4c = 1;
    w9->childHitTestFlag4d = 1;
    CRect layoutRect(0, 0, 0, 0);
    w9->contentInsets68.left = layoutRect.left;
    w9->contentInsets68.top = layoutRect.top;
    w9->contentInsets68.right = layoutRect.right;
    w9->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, -1, g_szEmptyString, 3, 0, 9, 0, -2);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w10 = new TStaticText();
    g_pUiResourceContext = w10;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w10;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w10);
    offset[0] = 0x78;
    offset[1] = 0xe0;
    size[0] = 0x40;
    size[1] = 0xe;
    w10->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w10->controlTag = static_cast<int>(0x74726561 /* 'trea' */);
    w10->controlValue3c = 0;
    w10->SetEnabled(1, 0);
    w10->SetState(0, 0);
    w10->inputGateFlag4c = 1;
    w10->childHitTestFlag4d = 1;
    w10->frameStyle60 = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w10->contentInsets68.left = layoutRect.left;
    w10->contentInsets68.top = layoutRect.top;
    w10->contentInsets68.right = layoutRect.right;
    w10->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, 3, g_szUiThousandDollars_00694B30, 3, 0, 9, 0, -1);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w11 = new TStaticText();
    g_pUiResourceContext = w11;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w11;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w11);
    offset[0] = 0x69;
    offset[1] = 0xc;
    size[0] = 0xa1;
    size[1] = 0x1e;
    w11->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w11->controlTag = static_cast<int>(0x7469746c /* 'titl' */);
    w11->controlValue3c = 0;
    w11->SetEnabled(1, 0);
    w11->SetState(0, 0);
    w11->inputGateFlag4c = 1;
    w11->childHitTestFlag4d = 1;
    w11->frameStyle60 = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w11->contentInsets68.left = layoutRect.left;
    w11->contentInsets68.top = layoutRect.top;
    w11->contentInsets68.right = layoutRect.right;
    w11->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, 5, g_szUiUniversityTitle_00694B20, 3, 0, 0x18, 0, 1);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TStaticText* w12 = new TStaticText();
    g_pUiResourceContext = w12;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w12;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w12);
    offset[0] = 0x1c;
    offset[1] = 0x3c;
    size[0] = 0x99;
    size[1] = 0x10;
    w12->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w12->controlTag = static_cast<int>(0x756e6974 /* 'unit' */);
    w12->controlValue3c = 0;
    w12->SetEnabled(1, 0);
    w12->SetState(0, 0);
    w12->inputGateFlag4c = 1;
    w12->childHitTestFlag4d = 1;
    w12->frameStyle60 = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w12->contentInsets68.left = layoutRect.left;
    w12->contentInsets68.top = layoutRect.top;
    w12->contentInsets68.right = layoutRect.right;
    w12->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(0xfa0, -1, g_szEmptyString, 3, 1, 9, 0, 1);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TCluster* w13 = new TCluster();
    g_pUiResourceContext = w13;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w13;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w13);
    offset[0] = 0xcc;
    offset[1] = 0x31;
    size[0] = 0xa2;
    size[1] = 0x163;
    w13->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w13->controlTag = static_cast<int>(0x73656c65 /* 'sele' */);
    w13->controlValue3c = 0;
    w13->SetEnabled(1, 0);
    w13->SetState(0, 0);
    w13->inputGateFlag4c = 1;
    w13->childHitTestFlag4d = 1;
    w13->frameStyle60 = 5;
    CRect layoutRect(0, 0, 0, 0);
    w13->contentInsets68.left = layoutRect.left;
    w13->contentInsets68.top = layoutRect.top;
    w13->contentInsets68.right = layoutRect.right;
    w13->contentInsets68.bottom = layoutRect.bottom;
    g_pUiResourceContext = 0;
  }
  {
    TCluster* w14 = new TCluster();
    g_pUiResourceContext = w14;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w14;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w14);
    offset[0] = 0xb;
    offset[1] = 0x43;
    size[0] = 0x3d;
    size[1] = 0x19;
    w14->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w14->controlTag = static_cast<int>(0x636c7530 /* 'clu0' */);
    w14->controlValue3c = 0;
    w14->SetEnabled(1, 0);
    w14->SetState(0, 0);
    w14->inputGateFlag4c = 1;
    w14->childHitTestFlag4d = 1;
    w14->frameStyle60 = 5;
    CRect layoutRect(0, 0, 0, 0);
    w14->contentInsets68.left = layoutRect.left;
    w14->contentInsets68.top = layoutRect.top;
    w14->contentInsets68.right = layoutRect.right;
    w14->contentInsets68.bottom = layoutRect.bottom;
    g_pUiResourceContext = 0;
  }
  {
    TPicture* w15 = new TPicture();
    g_pUiResourceContext = w15;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w15;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w15);
    offset[0] = 0x15;
    offset[1] = 0;
    size[0] = 0x12;
    size[1] = 0x14;
    w15->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w15->controlTag = static_cast<int>(0x6e756d30 /* 'num0' */);
    w15->controlValue3c = 0;
    w15->SetEnabled(1, 0);
    w15->SetState(0, 0);
    w15->inputGateFlag4c = 1;
    w15->childHitTestFlag4d = 1;
    w15->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w15->contentInsets68.left = layoutRect.left;
    w15->contentInsets68.top = layoutRect.top;
    w15->contentInsets68.right = layoutRect.right;
    w15->contentInsets68.bottom = layoutRect.bottom;
    w15->SetPictureResourceIdAndRefresh(0x26b2, 0);
    g_pUiResourceContext = 0;
  }
  {
    TNumberText* w16 = new TNumberText();
    g_pUiResourceContext = w16;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w16;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w16);
    offset[0] = -1;
    offset[1] = 0;
    size[0] = 0x13;
    size[1] = 0x11;
    w16->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w16->controlTag = static_cast<int>(0x6e756d62 /* 'numb' */);
    w16->controlValue3c = 0;
    w16->SetEnabled(1, 0);
    w16->SetState(0, 0);
    w16->inputGateFlag4c = 1;
    w16->childHitTestFlag4d = 0;
    delete w16->stylePayload48;
    w16->stylePayload48 = new TUiStyleBytes();
    w16->stylePayload48->styleWord = 0;
    w16->stylePayload48->packedColor = 0x6ac9c0;
    w16->frameStyle60 = 6;
    CRect layoutRect(3, 3, 3, 3);
    w16->contentInsets68.left = layoutRect.left;
    w16->contentInsets68.top = layoutRect.top;
    w16->contentInsets68.right = layoutRect.right;
    w16->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    w16->AssertValid();
    w16->field_9c = 0xff;
    w16->AssertValid();
    w16->field_a4 = 0;
    w16->field_a8 = 0xff;
    w16->SetControlValue(0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w17 = new TUpDownPictureButton();
    g_pUiResourceContext = w17;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w17;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w17);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w17->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w17->controlTag = static_cast<int>(0x6d696e75 /* 'minu' */);
    w17->controlValue3c = 0;
    w17->SetEnabled(1, 0);
    w17->SetState(1, 0);
    w17->inputGateFlag4c = 1;
    w17->childHitTestFlag4d = 1;
    w17->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w17->contentInsets68.left = layoutRect.left;
    w17->contentInsets68.top = layoutRect.top;
    w17->contentInsets68.right = layoutRect.right;
    w17->contentInsets68.bottom = layoutRect.bottom;
    w17->SetPictureResourceIdAndRefresh(0x26ad, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w18 = new TUpDownPictureButton();
    g_pUiResourceContext = w18;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w18;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w18);
    offset[0] = 0x28;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w18->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w18->controlTag = static_cast<int>(0x706c7573 /* 'plus' */);
    w18->controlValue3c = 0;
    w18->SetEnabled(1, 0);
    w18->SetState(1, 0);
    w18->inputGateFlag4c = 1;
    w18->childHitTestFlag4d = 1;
    w18->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w18->contentInsets68.left = layoutRect.left;
    w18->contentInsets68.top = layoutRect.top;
    w18->contentInsets68.right = layoutRect.right;
    w18->contentInsets68.bottom = layoutRect.bottom;
    w18->SetPictureResourceIdAndRefresh(0x26af, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TRadioPictureButton* w19 = new TRadioPictureButton();
    g_pUiResourceContext = w19;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w19;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w19);
    offset[0] = 9;
    offset[1] = 7;
    size[0] = 0x40;
    size[1] = 0x3c;
    w19->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w19->controlTag = static_cast<int>(0x63697630 /* 'civ0' */);
    w19->controlValue3c = 0;
    w19->SetEnabled(1, 0);
    w19->SetState(1, 0);
    w19->inputGateFlag4c = 1;
    w19->childHitTestFlag4d = 1;
    w19->frameStyle60 = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w19->contentInsets68.left = layoutRect.left;
    w19->contentInsets68.top = layoutRect.top;
    w19->contentInsets68.right = layoutRect.right;
    w19->contentInsets68.bottom = layoutRect.bottom;
    w19->SetPictureResourceIdAndRefresh(0x26c0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TRadioPictureButton* w20 = new TRadioPictureButton();
    g_pUiResourceContext = w20;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w20;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w20);
    offset[0] = 0x58;
    offset[1] = 7;
    size[0] = 0x40;
    size[1] = 0x3c;
    w20->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w20->controlTag = static_cast<int>(0x63697631 /* 'civ1' */);
    w20->controlValue3c = 0;
    w20->SetEnabled(1, 0);
    w20->SetState(1, 0);
    w20->inputGateFlag4c = 1;
    w20->childHitTestFlag4d = 1;
    w20->frameStyle60 = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w20->contentInsets68.left = layoutRect.left;
    w20->contentInsets68.top = layoutRect.top;
    w20->contentInsets68.right = layoutRect.right;
    w20->contentInsets68.bottom = layoutRect.bottom;
    w20->SetPictureResourceIdAndRefresh(0x26c2, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TCluster* w21 = new TCluster();
    g_pUiResourceContext = w21;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w21;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w21);
    offset[0] = 0x5a;
    offset[1] = 0x43;
    size[0] = 0x3d;
    size[1] = 0x19;
    w21->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w21->controlTag = static_cast<int>(0x636c7531 /* 'clu1' */);
    w21->controlValue3c = 0;
    w21->SetEnabled(1, 0);
    w21->SetState(0, 0);
    w21->inputGateFlag4c = 1;
    w21->childHitTestFlag4d = 1;
    w21->frameStyle60 = 5;
    CRect layoutRect(0, 0, 0, 0);
    w21->contentInsets68.left = layoutRect.left;
    w21->contentInsets68.top = layoutRect.top;
    w21->contentInsets68.right = layoutRect.right;
    w21->contentInsets68.bottom = layoutRect.bottom;
    g_pUiResourceContext = 0;
  }
  {
    TPicture* w22 = new TPicture();
    g_pUiResourceContext = w22;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w22;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w22);
    offset[0] = 0x15;
    offset[1] = 0;
    size[0] = 0x12;
    size[1] = 0x14;
    w22->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w22->controlTag = static_cast<int>(0x6e756d31 /* 'num1' */);
    w22->controlValue3c = 0;
    w22->SetEnabled(1, 0);
    w22->SetState(0, 0);
    w22->inputGateFlag4c = 1;
    w22->childHitTestFlag4d = 1;
    w22->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w22->contentInsets68.left = layoutRect.left;
    w22->contentInsets68.top = layoutRect.top;
    w22->contentInsets68.right = layoutRect.right;
    w22->contentInsets68.bottom = layoutRect.bottom;
    w22->SetPictureResourceIdAndRefresh(0x26b2, 0);
    g_pUiResourceContext = 0;
  }
  {
    TNumberText* w23 = new TNumberText();
    g_pUiResourceContext = w23;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w23;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w23);
    offset[0] = -1;
    offset[1] = 0;
    size[0] = 0x13;
    size[1] = 0x11;
    w23->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w23->controlTag = static_cast<int>(0x6e756d62 /* 'numb' */);
    w23->controlValue3c = 0;
    w23->SetEnabled(1, 0);
    w23->SetState(0, 0);
    w23->inputGateFlag4c = 1;
    w23->childHitTestFlag4d = 0;
    delete w23->stylePayload48;
    w23->stylePayload48 = new TUiStyleBytes();
    w23->stylePayload48->styleWord = 0;
    w23->stylePayload48->packedColor = 0x6ac9c0;
    w23->frameStyle60 = 6;
    CRect layoutRect(3, 3, 3, 3);
    w23->contentInsets68.left = layoutRect.left;
    w23->contentInsets68.top = layoutRect.top;
    w23->contentInsets68.right = layoutRect.right;
    w23->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    w23->AssertValid();
    w23->field_9c = 0xff;
    w23->AssertValid();
    w23->field_a4 = 0;
    w23->field_a8 = 0xff;
    w23->SetControlValue(0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w24 = new TUpDownPictureButton();
    g_pUiResourceContext = w24;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w24;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w24);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w24->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w24->controlTag = static_cast<int>(0x6d696e75 /* 'minu' */);
    w24->controlValue3c = 0;
    w24->SetEnabled(1, 0);
    w24->SetState(1, 0);
    w24->inputGateFlag4c = 1;
    w24->childHitTestFlag4d = 1;
    w24->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w24->contentInsets68.left = layoutRect.left;
    w24->contentInsets68.top = layoutRect.top;
    w24->contentInsets68.right = layoutRect.right;
    w24->contentInsets68.bottom = layoutRect.bottom;
    w24->SetPictureResourceIdAndRefresh(0x26ad, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w25 = new TUpDownPictureButton();
    g_pUiResourceContext = w25;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w25;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w25);
    offset[0] = 0x28;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w25->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w25->controlTag = static_cast<int>(0x706c7573 /* 'plus' */);
    w25->controlValue3c = 0;
    w25->SetEnabled(1, 0);
    w25->SetState(1, 0);
    w25->inputGateFlag4c = 1;
    w25->childHitTestFlag4d = 1;
    w25->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w25->contentInsets68.left = layoutRect.left;
    w25->contentInsets68.top = layoutRect.top;
    w25->contentInsets68.right = layoutRect.right;
    w25->contentInsets68.bottom = layoutRect.bottom;
    w25->SetPictureResourceIdAndRefresh(0x26af, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TRadioPictureButton* w26 = new TRadioPictureButton();
    g_pUiResourceContext = w26;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w26;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w26);
    offset[0] = 9;
    offset[1] = 0x5b;
    size[0] = 0x40;
    size[1] = 0x3c;
    w26->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w26->controlTag = static_cast<int>(0x63697632 /* 'civ2' */);
    w26->controlValue3c = 0;
    w26->SetEnabled(1, 0);
    w26->SetState(1, 0);
    w26->inputGateFlag4c = 1;
    w26->childHitTestFlag4d = 1;
    w26->frameStyle60 = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w26->contentInsets68.left = layoutRect.left;
    w26->contentInsets68.top = layoutRect.top;
    w26->contentInsets68.right = layoutRect.right;
    w26->contentInsets68.bottom = layoutRect.bottom;
    w26->SetPictureResourceIdAndRefresh(0x26c4, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TCluster* w27 = new TCluster();
    g_pUiResourceContext = w27;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w27;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w27);
    offset[0] = 0xb;
    offset[1] = 0x97;
    size[0] = 0x3d;
    size[1] = 0x19;
    w27->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w27->controlTag = static_cast<int>(0x636c7532 /* 'clu2' */);
    w27->controlValue3c = 0;
    w27->SetEnabled(1, 0);
    w27->SetState(0, 0);
    w27->inputGateFlag4c = 1;
    w27->childHitTestFlag4d = 1;
    w27->frameStyle60 = 5;
    CRect layoutRect(0, 0, 0, 0);
    w27->contentInsets68.left = layoutRect.left;
    w27->contentInsets68.top = layoutRect.top;
    w27->contentInsets68.right = layoutRect.right;
    w27->contentInsets68.bottom = layoutRect.bottom;
    g_pUiResourceContext = 0;
  }
  {
    TPicture* w28 = new TPicture();
    g_pUiResourceContext = w28;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w28;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w28);
    offset[0] = 0x15;
    offset[1] = 0;
    size[0] = 0x12;
    size[1] = 0x14;
    w28->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w28->controlTag = static_cast<int>(0x6e756d32 /* 'num2' */);
    w28->controlValue3c = 0;
    w28->SetEnabled(1, 0);
    w28->SetState(0, 0);
    w28->inputGateFlag4c = 1;
    w28->childHitTestFlag4d = 1;
    w28->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w28->contentInsets68.left = layoutRect.left;
    w28->contentInsets68.top = layoutRect.top;
    w28->contentInsets68.right = layoutRect.right;
    w28->contentInsets68.bottom = layoutRect.bottom;
    w28->SetPictureResourceIdAndRefresh(0x26b2, 0);
    g_pUiResourceContext = 0;
  }
  {
    TNumberText* w29 = new TNumberText();
    g_pUiResourceContext = w29;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w29;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w29);
    offset[0] = -1;
    offset[1] = 0;
    size[0] = 0x13;
    size[1] = 0x11;
    w29->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w29->controlTag = static_cast<int>(0x6e756d62 /* 'numb' */);
    w29->controlValue3c = 0;
    w29->SetEnabled(1, 0);
    w29->SetState(0, 0);
    w29->inputGateFlag4c = 1;
    w29->childHitTestFlag4d = 0;
    delete w29->stylePayload48;
    w29->stylePayload48 = new TUiStyleBytes();
    w29->stylePayload48->styleWord = 0;
    w29->stylePayload48->packedColor = 0x6ac9c0;
    w29->frameStyle60 = 6;
    CRect layoutRect(3, 3, 3, 3);
    w29->contentInsets68.left = layoutRect.left;
    w29->contentInsets68.top = layoutRect.top;
    w29->contentInsets68.right = layoutRect.right;
    w29->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    w29->AssertValid();
    w29->field_9c = 0xff;
    w29->AssertValid();
    w29->field_a4 = 0;
    w29->field_a8 = 0xff;
    w29->SetControlValue(0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w30 = new TUpDownPictureButton();
    g_pUiResourceContext = w30;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w30;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w30);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w30->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w30->controlTag = static_cast<int>(0x6d696e75 /* 'minu' */);
    w30->controlValue3c = 0;
    w30->SetEnabled(1, 0);
    w30->SetState(1, 0);
    w30->inputGateFlag4c = 1;
    w30->childHitTestFlag4d = 1;
    w30->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w30->contentInsets68.left = layoutRect.left;
    w30->contentInsets68.top = layoutRect.top;
    w30->contentInsets68.right = layoutRect.right;
    w30->contentInsets68.bottom = layoutRect.bottom;
    w30->SetPictureResourceIdAndRefresh(0x26ad, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w31 = new TUpDownPictureButton();
    g_pUiResourceContext = w31;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w31;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w31);
    offset[0] = 0x28;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w31->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w31->controlTag = static_cast<int>(0x706c7573 /* 'plus' */);
    w31->controlValue3c = 0;
    w31->SetEnabled(1, 0);
    w31->SetState(1, 0);
    w31->inputGateFlag4c = 1;
    w31->childHitTestFlag4d = 1;
    w31->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w31->contentInsets68.left = layoutRect.left;
    w31->contentInsets68.top = layoutRect.top;
    w31->contentInsets68.right = layoutRect.right;
    w31->contentInsets68.bottom = layoutRect.bottom;
    w31->SetPictureResourceIdAndRefresh(0x26af, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TRadioPictureButton* w32 = new TRadioPictureButton();
    g_pUiResourceContext = w32;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w32;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w32);
    offset[0] = 0x58;
    offset[1] = 0x5b;
    size[0] = 0x40;
    size[1] = 0x3c;
    w32->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w32->controlTag = static_cast<int>(0x63697633 /* 'civ3' */);
    w32->controlValue3c = 0;
    w32->SetEnabled(1, 0);
    w32->SetState(1, 0);
    w32->inputGateFlag4c = 1;
    w32->childHitTestFlag4d = 1;
    w32->frameStyle60 = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w32->contentInsets68.left = layoutRect.left;
    w32->contentInsets68.top = layoutRect.top;
    w32->contentInsets68.right = layoutRect.right;
    w32->contentInsets68.bottom = layoutRect.bottom;
    w32->SetPictureResourceIdAndRefresh(0x26c6, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TCluster* w33 = new TCluster();
    g_pUiResourceContext = w33;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w33;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w33);
    offset[0] = 0x5a;
    offset[1] = 0x97;
    size[0] = 0x3d;
    size[1] = 0x19;
    w33->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w33->controlTag = static_cast<int>(0x636c7533 /* 'clu3' */);
    w33->controlValue3c = 0;
    w33->SetEnabled(1, 0);
    w33->SetState(0, 0);
    w33->inputGateFlag4c = 1;
    w33->childHitTestFlag4d = 1;
    w33->frameStyle60 = 5;
    CRect layoutRect(0, 0, 0, 0);
    w33->contentInsets68.left = layoutRect.left;
    w33->contentInsets68.top = layoutRect.top;
    w33->contentInsets68.right = layoutRect.right;
    w33->contentInsets68.bottom = layoutRect.bottom;
    g_pUiResourceContext = 0;
  }
  {
    TPicture* w34 = new TPicture();
    g_pUiResourceContext = w34;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w34;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w34);
    offset[0] = 0x15;
    offset[1] = 0;
    size[0] = 0x12;
    size[1] = 0x14;
    w34->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w34->controlTag = static_cast<int>(0x6e756d33 /* 'num3' */);
    w34->controlValue3c = 0;
    w34->SetEnabled(1, 0);
    w34->SetState(0, 0);
    w34->inputGateFlag4c = 1;
    w34->childHitTestFlag4d = 1;
    w34->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w34->contentInsets68.left = layoutRect.left;
    w34->contentInsets68.top = layoutRect.top;
    w34->contentInsets68.right = layoutRect.right;
    w34->contentInsets68.bottom = layoutRect.bottom;
    w34->SetPictureResourceIdAndRefresh(0x26b2, 0);
    g_pUiResourceContext = 0;
  }
  {
    TNumberText* w35 = new TNumberText();
    g_pUiResourceContext = w35;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w35;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w35);
    offset[0] = -1;
    offset[1] = 0;
    size[0] = 0x13;
    size[1] = 0x11;
    w35->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w35->controlTag = static_cast<int>(0x6e756d62 /* 'numb' */);
    w35->controlValue3c = 0;
    w35->SetEnabled(1, 0);
    w35->SetState(0, 0);
    w35->inputGateFlag4c = 1;
    w35->childHitTestFlag4d = 0;
    delete w35->stylePayload48;
    w35->stylePayload48 = new TUiStyleBytes();
    w35->stylePayload48->styleWord = 0;
    w35->stylePayload48->packedColor = 0x6ac9c0;
    w35->frameStyle60 = 6;
    CRect layoutRect(3, 3, 3, 3);
    w35->contentInsets68.left = layoutRect.left;
    w35->contentInsets68.top = layoutRect.top;
    w35->contentInsets68.right = layoutRect.right;
    w35->contentInsets68.bottom = layoutRect.bottom;
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    w35->AssertValid();
    w35->field_9c = 0xff;
    w35->AssertValid();
    w35->field_a4 = 0;
    w35->field_a8 = 0xff;
    w35->SetControlValue(0, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w36 = new TUpDownPictureButton();
    g_pUiResourceContext = w36;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w36;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w36);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w36->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w36->controlTag = static_cast<int>(0x6d696e75 /* 'minu' */);
    w36->controlValue3c = 0;
    w36->SetEnabled(1, 0);
    w36->SetState(1, 0);
    w36->inputGateFlag4c = 1;
    w36->childHitTestFlag4d = 1;
    w36->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w36->contentInsets68.left = layoutRect.left;
    w36->contentInsets68.top = layoutRect.top;
    w36->contentInsets68.right = layoutRect.right;
    w36->contentInsets68.bottom = layoutRect.bottom;
    w36->SetPictureResourceIdAndRefresh(0x26ad, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  {
    TUpDownPictureButton* w37 = new TUpDownPictureButton();
    g_pUiResourceContext = w37;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w37;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w37);
    offset[0] = 0x28;
    offset[1] = 0;
    size[0] = 0x14;
    size[1] = 0x14;
    w37->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w37->controlTag = static_cast<int>(0x706c7573 /* 'plus' */);
    w37->controlValue3c = 0;
    w37->SetEnabled(1, 0);
    w37->SetState(1, 0);
    w37->inputGateFlag4c = 1;
    w37->childHitTestFlag4d = 1;
    w37->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w37->contentInsets68.left = layoutRect.left;
    w37->contentInsets68.top = layoutRect.top;
    w37->contentInsets68.right = layoutRect.right;
    w37->contentInsets68.bottom = layoutRect.bottom;
    w37->SetPictureResourceIdAndRefresh(0x26af, 0);
    g_pUiResourceContext = 0;
  }
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  {
    TCluster* w38 = new TCluster();
    g_pUiResourceContext = w38;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w38;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w38);
    offset[0] = 0xb;
    offset[1] = 0xeb;
    size[0] = 0x3d;
    size[1] = 0x19;
    w38->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w38->controlTag = static_cast<int>(0x636c7534 /* 'clu4' */);
    w38->controlValue3c = 0;
    w38->SetEnabled(1, 0);
    w38->SetState(0, 0);
    w38->inputGateFlag4c = 1;
    w38->childHitTestFlag4d = 1;
    w38->frameStyle60 = 5;
    CRect layoutRect(0, 0, 0, 0);
    w38->contentInsets68.left = layoutRect.left;
    w38->contentInsets68.top = layoutRect.top;
    w38->contentInsets68.right = layoutRect.right;
    w38->contentInsets68.bottom = layoutRect.bottom;
    g_pUiResourceContext = 0;
  }
  {
    TPicture* w39 = new TPicture();
    g_pUiResourceContext = w39;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w39;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w39);
    offset[0] = 0x15;
    offset[1] = 0;
    size[0] = 0x12;
    size[1] = 0x14;
    w39->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w39->controlTag = static_cast<int>(0x6e756d34 /* 'num4' */);
    w39->controlValue3c = 0;
    w39->SetEnabled(1, 0);
    w39->SetState(0, 0);
    w39->inputGateFlag4c = 1;
    w39->childHitTestFlag4d = 1;
    w39->frameStyle60 = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w39->contentInsets68.left = layoutRect.left;
    w39->contentInsets68.top = layoutRect.top;
    w39->contentInsets68.right = layoutRect.right;
    w39->contentInsets68.bottom = layoutRect.bottom;
    w39->SetPictureResourceIdAndRefresh(0x26b2, 0);
    g_pUiResourceContext = 0;
  }
  {
    TNumberText* w40 = new TNumberText();
    g_pUiResourceContext = w40;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = w40;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(w40);
    offset[0] = -1;
    offset[1] = 0;
    size[0] = 0x13;
    size[1] = 0x11;
    w40->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    w40->controlTag = static_cast<int>(0x6e756d62 /* 'numb' */);
    w40->controlValue3c = 0;
    w40->SetEnabled(1, 0);
    w40->SetState(0, 0);
    w40->inputGateFlag4c = 1;
    w40->childHitTestFlag4d = 0;
    delete w40->stylePayload48;
    w40->stylePayload48 = new TUiStyleBytes();
    w40->stylePayload48->styleWord = 0;
    w40->stylePayload48->packedColor = 6;
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    SetUiResourceContextMaxCharCount(0xff);
    SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x6e756d62 /* 'numb' */);
  PopUiResourcePoolNode(0x6e756d34 /* 'num4' */);
  {
    TUpDownPictureButton* w41 = new TUpDownPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d696e75 /* 'minu' */, w41, 0, 0, 0x14, 0x14,
                            1, 1, 0x636c7534, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26ad);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x6d696e75 /* 'minu' */);
  {
    TUpDownPictureButton* w43 = new TUpDownPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x706c7573 /* 'plus' */, w43, 0x28, 0, 0x14,
                            0x14, 1, 1, 0x636c7534, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26af);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x706c7573 /* 'plus' */);
  PopUiResourcePoolNode(0x636c7534 /* 'clu4' */);
  {
    TRadioPictureButton* w45 = new TRadioPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x63697634 /* 'civ4' */, w45, 9, 0xaf, 0x40,
                            0x3c, 1, 1, 0x73656c65, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26c8);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x63697634 /* 'civ4' */);
  {
    TRadioPictureButton* w47 = new TRadioPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x63697638 /* 'civ8' */, w47, 0x58, 0x103,
                            0x40, 0x3c, 1, 1, 0x73656c65, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26d0);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x63697638 /* 'civ8' */);
  {
    TCluster* w49 = new TCluster();
    RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x636c7538 /* 'clu8' */, w49, 0x5a, 0x13f,
                            0x3d, 0x19, 0, 1, 0x73656c65, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();
  }
  {
    TPicture* w51 = new TPicture();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6e756d38 /* 'num8' */, w51, 0x15, 0, 0x12,
                            0x14, 0, 1, 0x636c7538, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26b2);
    ClearUiResourceContext();
  }
  {
    TNumberText* w53 = new TNumberText();
    RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d62 /* 'numb' */, w53, -1, 0, 0x13,
                            0x11, 0, 1, 0x6e756d38, 0);
    SetUiResourceStateFlags(1, 0);
    ReplaceUiResourceContextPairBuffer(0, 0x6ac9c0);
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    SetUiResourceContextMaxCharCount(0xff);
    SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x6e756d62 /* 'numb' */);
  PopUiResourcePoolNode(0x6e756d38 /* 'num8' */);
  {
    TUpDownPictureButton* w55 = new TUpDownPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d696e75 /* 'minu' */, w55, 0, 0, 0x14, 0x14,
                            1, 1, 0x636c7538, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26ad);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x6d696e75 /* 'minu' */);
  {
    TUpDownPictureButton* w57 = new TUpDownPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x706c7573 /* 'plus' */, w57, 0x28, 0, 0x14,
                            0x14, 1, 1, 0x636c7538, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26af);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x706c7573 /* 'plus' */);
  PopUiResourcePoolNode(0x636c7538 /* 'clu8' */);
  {
    TCluster* w59 = new TCluster();
    RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x636c7535 /* 'clu5' */, w59, 0x5a, 0xeb, 0x3d,
                            0x19, 0, 1, 0x73656c65, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();
  }
  {
    TPicture* w61 = new TPicture();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6e756d35 /* 'num5' */, w61, 0x15, 0, 0x12,
                            0x14, 0, 1, 0x636c7535, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26b2);
    ClearUiResourceContext();
  }
  {
    TNumberText* w63 = new TNumberText();
    RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d62 /* 'numb' */, w63, -1, 0, 0x13,
                            0x11, 0, 1, 0x6e756d35, 0);
    SetUiResourceStateFlags(1, 0);
    ReplaceUiResourceContextPairBuffer(0, 0x6ac9c0);
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 3, 0, 9, 0, 1);
    SetUiResourceContextMaxCharCount(0xff);
    SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x6e756d62 /* 'numb' */);
  PopUiResourcePoolNode(0x6e756d35 /* 'num5' */);
  {
    TUpDownPictureButton* w65 = new TUpDownPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d696e75 /* 'minu' */, w65, 0, 0, 0x14, 0x14,
                            1, 1, 0x636c7535, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26ad);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x6d696e75 /* 'minu' */);
  {
    TUpDownPictureButton* w67 = new TUpDownPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x706c7573 /* 'plus' */, w67, 0x28, 0, 0x14,
                            0x14, 1, 1, 0x636c7535, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26af);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x706c7573 /* 'plus' */);
  PopUiResourcePoolNode(0x636c7535 /* 'clu5' */);
  {
    TRadioPictureButton* w69 = new TRadioPictureButton();
    RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x63697635 /* 'civ5' */, w69, 0x58, 0xaf, 0x40,
                            0x3c, 1, 1, 0x73656c65, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x26ca);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x63697635 /* 'civ5' */);
  PopUiResourcePoolNode(0x73656c65 /* 'sele' */);
  {
    TNumberText* w71 = new TNumberText();
    RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x63657870 /* 'cexp' */, w71, 0x25, 0xba, 0x17,
                            0x15, 0, 1, 0x444c4f47, 0);
    SetUiResourceStateFlags(1, 0);
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderOne_006943AC, 3, 0, 9, 0, 0);
    SetUiResourceContextMaxCharCount(0xff);
    SetUiResourceContextNumberValueAndRange(1, 0, 0xff);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x63657870 /* 'cexp' */);
  {
    TNumberText* w73 = new TNumberText();
    RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x61657870 /* 'aexp' */, w73, 0x25, 0xe5, 0x17,
                            0x15, 0, 1, 0x444c4f47, 0);
    SetUiResourceStateFlags(1, 0);
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderOne_006943AC, 3, 0, 9, 0, 0);
    SetUiResourceContextMaxCharCount(0xff);
    SetUiResourceContextNumberValueAndRange(1, 0, 0xff);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x61657870 /* 'aexp' */);
  {
    TStaticText* w75 = new TStaticText();
    RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x66697833 /* 'fix3' */, w75, 0x65, 0xfe, 0x24,
                            0x1a, 0, 1, 0x444c4f47, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0xfa0, 4, g_szUiLevel1_00694B38, 3, 0, 9, 0, -2);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x66697833 /* 'fix3' */);
  {
    TStaticText* w77 = new TStaticText();
    RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x66697834 /* 'fix4' */, w77, 0x8d, 0xfe, 0x24,
                            0x1a, 0, 1, 0x444c4f47, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0xfa0, 4, g_szUiLevel1_00694B38, 3, 0, 9, 0, -2);
    ClearUiResourceContext();
  }
  PopUiResourcePoolNode(0x66697834 /* 'fix4' */);
  PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
  PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
