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

// Main-menu screen (event 0x5dc): a 2000x2000 'base' container holding a full-screen
// 640x480 'main' TGameSetupPicture (bitmap 0x1194), seven 'cntl' TControl hotspots
// (load/rand/mult/high/scen/quit/pref), and a 'tevw'/'curs' TInfoBarText info bar
// between 'scen' and 'quit'.
//
// TODO(bd 1uj.57.5 follow-up): only event 0x5dc is wired. The dispatcher's other
// reachable branches -- exact cases 0x3b8 (strategic-map screen) and 0x3b9 (a GOLD
// dialog), the <=0x3c6 range, the 0x5dd-0x5e5/0x5eb jump-table cases (new-game setup,
// multiplayer setup, etc.), and the >0x5eb default -- are still unported. Ghidra's
// recorded bounds for this function (13059 bytes) are also known to be wrong (real
// code continues past 0x458cd1); see the bd 1uj.57.5 2026-07-06 comment for the full
// case-to-address map, decodable again via `just decode-builder 0x4538a0`.
// Screen-builder dispatcher for the setup/menu family of events. One switch in the
// original: MSVC500 lowers the sparse case set (0x3b8/0x3b9/0x3c6/0x4e20/0x5eb) to a
// comparison tree and the dense 0x5dc-0x5e5 run to the jump table at 0x459548, with
// the shared pop/propagate case tails cross-jump-merged (0x4543a5/0x4594f7/0x459511).
// FUNCTION: IMPERIALISM 0x004538a0
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  switch (static_cast<short>(nEventCode)) {
  // Multiplayer/net-select setup screen (event 0x5e2): expanded-idiom widget tree
  // (TNetSelectPicture 'main', okay/cancel picture buttons, join/host controls,
  // game-name edit row, TTextList rosters and their scroll buttons).
  case 0x5e2: {
    {
      TView* w1 = new TView();
      g_pUiResourceContext = w1;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w1;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w1);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x7d0;
      size[1] = 0x7d0;
      w1->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w1->controlTag = static_cast<int>(0x62617365 /* 'base' */);
      w1->controlValue3c = 0;
      w1->SetEnabled(1, 0);
      w1->SetState(0, 0);
      w1->inputGateFlag4c = 1;
      w1->childHitTestFlag4d = 1;
      g_pUiResourceContext = 0;
    }
    {
      TNetSelectPicture* w2 = new TNetSelectPicture();
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
      size[0] = 0x280;
      size[1] = 0x1e0;
      w2->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w2->controlTag = static_cast<int>(0x6d61696e /* 'main' */);
      w2->controlValue3c = 0;
      w2->SetEnabled(1, 0);
      w2->SetState(0, 0);
      w2->inputGateFlag4c = 1;
      w2->childHitTestFlag4d = 1;
      delete w2->stylePayload48;
      w2->stylePayload48 = new TUiStyleBytes();
      w2->stylePayload48->styleWord = 0;
      w2->stylePayload48->packedColor = 0xffffff;
      w2->frameStyle60 = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w2->contentInsets68.left = layoutRect.left;
      w2->contentInsets68.top = layoutRect.top;
      w2->contentInsets68.right = layoutRect.right;
      w2->contentInsets68.bottom = layoutRect.bottom;
      w2->SetPictureResourceIdAndRefresh(0x1068, 0);
      g_pUiResourceContext = 0;
    }
    {
      TPictureButton* w3 = new TPictureButton();
      g_pUiResourceContext = w3;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w3;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w3);
      offset[0] = 0x221;
      offset[1] = 0x1bc;
      size[0] = 0x4b;
      size[1] = 0x24;
      w3->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w3->controlTag = static_cast<int>(0x6f6b6179 /* 'okay' */);
      w3->controlValue3c = 0;
      w3->SetEnabled(0, 0);
      w3->SetState(1, 0);
      w3->inputGateFlag4c = 1;
      w3->childHitTestFlag4d = 1;
      w3->frameStyle60 = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w3->contentInsets68.left = layoutRect.left;
      w3->contentInsets68.top = layoutRect.top;
      w3->contentInsets68.right = layoutRect.right;
      w3->contentInsets68.bottom = layoutRect.bottom;
      w3->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPictureButton* w4 = new TPictureButton();
      g_pUiResourceContext = w4;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w4;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w4);
      offset[0] = 0x15;
      offset[1] = 0x1bc;
      size[0] = 0x4b;
      size[1] = 0x24;
      w4->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w4->controlTag = static_cast<int>(0x636e636c /* 'cncl' */);
      w4->controlValue3c = 0;
      w4->SetEnabled(0, 0);
      w4->SetState(1, 0);
      w4->inputGateFlag4c = 1;
      w4->childHitTestFlag4d = 1;
      w4->frameStyle60 = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w4->contentInsets68.left = layoutRect.left;
      w4->contentInsets68.top = layoutRect.top;
      w4->contentInsets68.right = layoutRect.right;
      w4->contentInsets68.bottom = layoutRect.bottom;
      w4->SetPictureResourceIdAndRefresh(0x119f, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TMyStaticText* w5 = new TMyStaticText();
      g_pUiResourceContext = w5;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w5;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w5);
      offset[0] = 0x108;
      offset[1] = 0xab;
      size[0] = 0x8a;
      size[1] = 0x12;
      w5->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w5->controlTag = static_cast<int>(0x74787430 /* 'txt0' */);
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
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TMyStaticText* w6 = new TMyStaticText();
      g_pUiResourceContext = w6;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w6;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w6);
      offset[0] = 0x107;
      offset[1] = 0xce;
      size[0] = 0x8c;
      size[1] = 0xf;
      w6->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w6->controlTag = static_cast<int>(0x74787431 /* 'txt1' */);
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
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TMyStaticText* w7 = new TMyStaticText();
      g_pUiResourceContext = w7;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w7;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w7);
      offset[0] = 0x108;
      offset[1] = 0xed;
      size[0] = 0x8f;
      size[1] = 0x11;
      w7->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w7->controlTag = static_cast<int>(0x74787432 /* 'txt2' */);
      w7->controlValue3c = 0;
      w7->SetEnabled(1, 0);
      w7->SetState(0, 0);
      w7->inputGateFlag4c = 1;
      w7->childHitTestFlag4d = 1;
      w7->frameStyle60 = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w7->contentInsets68.left = layoutRect.left;
      w7->contentInsets68.top = layoutRect.top;
      w7->contentInsets68.right = layoutRect.right;
      w7->contentInsets68.bottom = layoutRect.bottom;
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TMyStaticText* w8 = new TMyStaticText();
      g_pUiResourceContext = w8;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w8;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w8);
      offset[0] = 0x108;
      offset[1] = 0x10e;
      size[0] = 0x8b;
      size[1] = 0x10;
      w8->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w8->controlTag = static_cast<int>(0x74787433 /* 'txt3' */);
      w8->controlValue3c = 0;
      w8->SetEnabled(1, 0);
      w8->SetState(0, 0);
      w8->inputGateFlag4c = 1;
      w8->childHitTestFlag4d = 1;
      w8->frameStyle60 = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w8->contentInsets68.left = layoutRect.left;
      w8->contentInsets68.top = layoutRect.top;
      w8->contentInsets68.right = layoutRect.right;
      w8->contentInsets68.bottom = layoutRect.bottom;
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TCluster* w9 = new TCluster();
      g_pUiResourceContext = w9;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w9;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w9);
      offset[0] = 0xde;
      offset[1] = 0x68;
      size[0] = 0x30;
      size[1] = 0xd0;
      w9->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w9->controlTag = static_cast<int>(0x70726f74 /* 'prot' */);
      w9->controlValue3c = 0;
      w9->SetEnabled(1, 0);
      w9->SetState(0, 0);
      w9->inputGateFlag4c = 1;
      w9->childHitTestFlag4d = 1;
      w9->frameStyle60 = 5;
      CRect layoutRect(0, 0, 0, 0);
      w9->contentInsets68.left = layoutRect.left;
      w9->contentInsets68.top = layoutRect.top;
      w9->contentInsets68.right = layoutRect.right;
      w9->contentInsets68.bottom = layoutRect.bottom;
      g_pUiResourceContext = 0;
    }
    {
      TRadioPictureButton* w10 = new TRadioPictureButton();
      g_pUiResourceContext = w10;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w10;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w10);
      offset[0] = 8;
      offset[1] = 0x3d;
      size[0] = 0x1f;
      size[1] = 0x1b;
      w10->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w10->controlTag = static_cast<int>(0x72616430 /* 'rad0' */);
      w10->controlValue3c = 0;
      w10->SetEnabled(1, 0);
      w10->SetState(1, 0);
      w10->inputGateFlag4c = 1;
      w10->childHitTestFlag4d = 1;
      w10->frameStyle60 = 0xc;
      CRect layoutRect(0, 0, 0, 0);
      w10->contentInsets68.left = layoutRect.left;
      w10->contentInsets68.top = layoutRect.top;
      w10->contentInsets68.right = layoutRect.right;
      w10->contentInsets68.bottom = layoutRect.bottom;
      w10->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TRadioPictureButton* w11 = new TRadioPictureButton();
      g_pUiResourceContext = w11;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w11;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w11);
      offset[0] = 7;
      offset[1] = 0x61;
      size[0] = 0x20;
      size[1] = 0x18;
      w11->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w11->controlTag = static_cast<int>(0x72616431 /* 'rad1' */);
      w11->controlValue3c = 0;
      w11->SetEnabled(1, 0);
      w11->SetState(1, 0);
      w11->inputGateFlag4c = 1;
      w11->childHitTestFlag4d = 1;
      CRect layoutRect(0, 0, 0, 0);
      w11->contentInsets68.left = layoutRect.left;
      w11->contentInsets68.top = layoutRect.top;
      w11->contentInsets68.right = layoutRect.right;
      w11->contentInsets68.bottom = layoutRect.bottom;
      w11->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TRadioPictureButton* w12 = new TRadioPictureButton();
      g_pUiResourceContext = w12;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w12;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w12);
      offset[0] = 7;
      offset[1] = 0x80;
      size[0] = 0x20;
      size[1] = 0x1a;
      w12->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w12->controlTag = static_cast<int>(0x72616432 /* 'rad2' */);
      w12->controlValue3c = 0;
      w12->SetEnabled(1, 0);
      w12->SetState(1, 0);
      w12->inputGateFlag4c = 1;
      w12->childHitTestFlag4d = 1;
      w12->frameStyle60 = 0xc;
      CRect layoutRect(0, 0, 0, 0);
      w12->contentInsets68.left = layoutRect.left;
      w12->contentInsets68.top = layoutRect.top;
      w12->contentInsets68.right = layoutRect.right;
      w12->contentInsets68.bottom = layoutRect.bottom;
      w12->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TRadioPictureButton* w13 = new TRadioPictureButton();
      g_pUiResourceContext = w13;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w13;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w13);
      offset[0] = 6;
      offset[1] = 0xa1;
      size[0] = 0x20;
      size[1] = 0x1a;
      w13->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w13->controlTag = static_cast<int>(0x72616433 /* 'rad3' */);
      w13->controlValue3c = 0;
      w13->SetEnabled(1, 0);
      w13->SetState(1, 0);
      w13->inputGateFlag4c = 1;
      w13->childHitTestFlag4d = 1;
      w13->frameStyle60 = 0xc;
      CRect layoutRect(0, 0, 0, 0);
      w13->contentInsets68.left = layoutRect.left;
      w13->contentInsets68.top = layoutRect.top;
      w13->contentInsets68.right = layoutRect.right;
      w13->contentInsets68.bottom = layoutRect.bottom;
      w13->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* w14 = new TUpDownPictureButton();
      g_pUiResourceContext = w14;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w14;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w14);
      offset[0] = 0x19d;
      offset[1] = 0xaa;
      size[0] = 0x1e;
      size[1] = 0x18;
      w14->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w14->controlTag = static_cast<int>(0x73657430 /* 'set0' */);
      w14->controlValue3c = 0;
      w14->SetEnabled(1, 0);
      w14->SetState(1, 0);
      w14->inputGateFlag4c = 1;
      w14->childHitTestFlag4d = 1;
      w14->frameStyle60 = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w14->contentInsets68.left = layoutRect.left;
      w14->contentInsets68.top = layoutRect.top;
      w14->contentInsets68.right = layoutRect.right;
      w14->contentInsets68.bottom = layoutRect.bottom;
      w14->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* w15 = new TUpDownPictureButton();
      g_pUiResourceContext = w15;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w15;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w15);
      offset[0] = 0x19c;
      offset[1] = 0xc9;
      size[0] = 0x1e;
      size[1] = 0x18;
      w15->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w15->controlTag = static_cast<int>(0x73657431 /* 'set1' */);
      w15->controlValue3c = 0;
      w15->SetEnabled(1, 0);
      w15->SetState(1, 0);
      w15->inputGateFlag4c = 1;
      w15->childHitTestFlag4d = 1;
      w15->frameStyle60 = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w15->contentInsets68.left = layoutRect.left;
      w15->contentInsets68.top = layoutRect.top;
      w15->contentInsets68.right = layoutRect.right;
      w15->contentInsets68.bottom = layoutRect.bottom;
      w15->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* w16 = new TUpDownPictureButton();
      g_pUiResourceContext = w16;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w16;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w16);
      offset[0] = 0x19e;
      offset[1] = 0xea;
      size[0] = 0x1e;
      size[1] = 0x18;
      w16->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w16->controlTag = static_cast<int>(0x73657432 /* 'set2' */);
      w16->controlValue3c = 0;
      w16->SetEnabled(1, 0);
      w16->SetState(1, 0);
      w16->inputGateFlag4c = 1;
      w16->childHitTestFlag4d = 1;
      w16->frameStyle60 = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w16->contentInsets68.left = layoutRect.left;
      w16->contentInsets68.top = layoutRect.top;
      w16->contentInsets68.right = layoutRect.right;
      w16->contentInsets68.bottom = layoutRect.bottom;
      w16->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
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
      offset[0] = 0x19c;
      offset[1] = 0x109;
      size[0] = 0x1e;
      size[1] = 0x18;
      w17->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w17->controlTag = static_cast<int>(0x73657433 /* 'set3' */);
      w17->controlValue3c = 0;
      w17->SetEnabled(1, 0);
      w17->SetState(1, 0);
      w17->inputGateFlag4c = 1;
      w17->childHitTestFlag4d = 1;
      w17->frameStyle60 = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w17->contentInsets68.left = layoutRect.left;
      w17->contentInsets68.top = layoutRect.top;
      w17->contentInsets68.right = layoutRect.right;
      w17->contentInsets68.bottom = layoutRect.bottom;
      w17->SetPictureResourceIdAndRefresh(0x119e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* w18 = new TStaticText();
      g_pUiResourceContext = w18;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w18;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w18);
      offset[0] = 0x15;
      offset[1] = 0x65;
      size[0] = 0x62;
      size[1] = 0x13;
      w18->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w18->controlTag = static_cast<int>(0x7467616d /* 'tgam' */);
      w18->controlValue3c = 0;
      w18->SetEnabled(1, 0);
      w18->SetState(0, 0);
      w18->inputGateFlag4c = 1;
      w18->childHitTestFlag4d = 1;
      w18->frameStyle60 = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w18->contentInsets68.left = layoutRect.left;
      w18->contentInsets68.top = layoutRect.top;
      w18->contentInsets68.right = layoutRect.right;
      w18->contentInsets68.bottom = layoutRect.bottom;
      BindUiResourceTextAndStyle(0x514, 0xf, g_szNewGameGameNameLabel_00694A88, 0, 0, 0, 0, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TEditText* w19 = new TEditText();
      g_pUiResourceContext = w19;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w19;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w19);
      offset[0] = 0x29;
      offset[1] = 0x7a;
      size[0] = 0x121;
      size[1] = 0x16;
      w19->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w19->controlTag = static_cast<int>(0x67616d65 /* 'game' */);
      w19->controlValue3c = 0;
      w19->SetEnabled(1, 0);
      w19->SetState(1, 0);
      w19->inputGateFlag4c = 1;
      w19->childHitTestFlag4d = 0;
      w19->frameStyle60 = 6;
      CRect layoutRect(3, 3, 3, 3);
      w19->contentInsets68.left = layoutRect.left;
      w19->contentInsets68.top = layoutRect.top;
      w19->contentInsets68.right = layoutRect.right;
      w19->contentInsets68.bottom = layoutRect.bottom;
      BindUiResourceTextAndStyle(0x514, 0x10, g_szNewGameScenarioPlaceholderTitle_00694A68, 0, 0, 0,
                                 0, 0);
      w19->AssertValid();
      w19->field_9c = 0xff;
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TInfoBarText* w20 = new TInfoBarText();
      g_pUiResourceContext = w20;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w20;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w20);
      offset[0] = 0x15;
      offset[1] = 0x43;
      size[0] = 0xc8;
      size[1] = 0x15;
      w20->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w20->controlTag = static_cast<int>(0x6c61626c /* 'labl' */);
      w20->controlValue3c = 0;
      w20->SetEnabled(1, 0);
      w20->SetState(0, 0);
      w20->inputGateFlag4c = 1;
      w20->childHitTestFlag4d = 0;
    }
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
  } break;

  // High-scores screen (event 0x5e0): THighScoresPicture panel with score text rows.
  case 0x5e0: {
    {
      TView* w1 = new TView();
      g_pUiResourceContext = w1;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w1;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w1);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x7d0;
      size[1] = 0x7d0;
      w1->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w1->controlTag = static_cast<int>(0x62617365 /* 'base' */);
      w1->controlValue3c = 0;
      w1->SetEnabled(1, 0);
      w1->SetState(0, 0);
      w1->inputGateFlag4c = 1;
      w1->childHitTestFlag4d = 1;
      g_pUiResourceContext = 0;
    }
    {
      THighScoresPicture* w2 = new THighScoresPicture();
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
      size[0] = 0x280;
      size[1] = 0x1e0;
      w2->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w2->controlTag = static_cast<int>(0x6d61696e /* 'main' */);
      w2->controlValue3c = 0;
      w2->SetEnabled(1, 0);
      w2->SetState(1, 0);
      w2->inputGateFlag4c = 1;
      w2->childHitTestFlag4d = 1;
      delete w2->stylePayload48;
      w2->stylePayload48 = new TUiStyleBytes();
      w2->stylePayload48->styleWord = 0;
      w2->stylePayload48->packedColor = 0xffffff;
      w2->frameStyle60 = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w2->contentInsets68.left = layoutRect.left;
      w2->contentInsets68.top = layoutRect.top;
      w2->contentInsets68.right = layoutRect.right;
      w2->contentInsets68.bottom = layoutRect.bottom;
      w2->SetPictureResourceIdAndRefresh(0x11ee, 0);
      g_pUiResourceContext = 0;
    }
    {
      TStaticText* w3 = new TStaticText();
      g_pUiResourceContext = w3;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w3;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w3);
      offset[0] = 0x1b;
      offset[1] = 0x44;
      size[0] = 0xea;
      size[1] = 0x12;
      w3->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w3->controlTag = static_cast<int>(0x6c61626c /* 'labl' */);
      w3->controlValue3c = 0;
      w3->SetEnabled(1, 0);
      w3->SetState(0, 0);
      w3->inputGateFlag4c = 1;
      w3->childHitTestFlag4d = 1;
      w3->frameStyle60 = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w3->contentInsets68.left = layoutRect.left;
      w3->contentInsets68.top = layoutRect.top;
      w3->contentInsets68.right = layoutRect.right;
      w3->contentInsets68.bottom = layoutRect.bottom;
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
  } break;

  // Special-quit / credits screen (event 0x4e20): TSpecialQuitPicture panel with
  // TDeluxeText caption rows ('requ' request text, 'titl' title).
  case 0x4e20: {
    {
      TView* w1 = new TView();
      g_pUiResourceContext = w1;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w1;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w1);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x7d0;
      size[1] = 0x7d0;
      w1->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w1->controlTag = static_cast<int>(0x62617365 /* 'base' */);
      w1->controlValue3c = 0;
      w1->SetEnabled(1, 0);
      w1->SetState(0, 0);
      w1->inputGateFlag4c = 1;
      w1->childHitTestFlag4d = 1;
      g_pUiResourceContext = 0;
    }
    {
      TSpecialQuitPicture* w2 = new TSpecialQuitPicture();
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
      size[0] = 0x280;
      size[1] = 0x1e0;
      w2->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w2->controlTag = static_cast<int>(0x6d61696e /* 'main' */);
      w2->controlValue3c = 0;
      w2->SetEnabled(1, 0);
      w2->SetState(1, 0);
      w2->inputGateFlag4c = 1;
      w2->childHitTestFlag4d = 1;
      delete w2->stylePayload48;
      w2->stylePayload48 = new TUiStyleBytes();
      w2->stylePayload48->styleWord = 0;
      w2->stylePayload48->packedColor = 0xffffff;
      w2->frameStyle60 = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w2->contentInsets68.left = layoutRect.left;
      w2->contentInsets68.top = layoutRect.top;
      w2->contentInsets68.right = layoutRect.right;
      w2->contentInsets68.bottom = layoutRect.bottom;
      w2->SetPictureResourceIdAndRefresh(0x4e20, 0);
      g_pUiResourceContext = 0;
    }
    {
      TDeluxeText* w3 = new TDeluxeText();
      g_pUiResourceContext = w3;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w3;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w3);
      offset[0] = 7;
      offset[1] = 6;
      size[0] = 0x18e;
      size[1] = 0x17b;
      w3->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w3->controlTag = static_cast<int>(0x73616c65 /* 'sale' */);
      w3->controlValue3c = 0;
      w3->SetEnabled(1, 0);
      w3->SetState(0, 0);
      w3->inputGateFlag4c = 1;
      w3->childHitTestFlag4d = 0;
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPictureButton* w4 = new TPictureButton();
      g_pUiResourceContext = w4;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w4;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w4);
      offset[0] = 0x4a;
      offset[1] = 0x190;
      size[0] = 0x61;
      size[1] = 0x25;
      w4->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w4->controlTag = static_cast<int>(0x73686f77 /* 'show' */);
      w4->controlValue3c = 0;
      w4->SetEnabled(0, 0);
      w4->SetState(1, 0);
      w4->inputGateFlag4c = 1;
      w4->childHitTestFlag4d = 1;
      w4->frameStyle60 = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w4->contentInsets68.left = layoutRect.left;
      w4->contentInsets68.top = layoutRect.top;
      w4->contentInsets68.right = layoutRect.right;
      w4->contentInsets68.bottom = layoutRect.bottom;
      w4->SetPictureResourceIdAndRefresh(0x4e21, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPictureButton* w5 = new TPictureButton();
      g_pUiResourceContext = w5;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w5;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w5);
      offset[0] = 0x1e3;
      offset[1] = 0x18f;
      size[0] = 0x61;
      size[1] = 0x25;
      w5->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w5->controlTag = static_cast<int>(0x71756974 /* 'quit' */);
      w5->controlValue3c = 0;
      w5->SetEnabled(0, 0);
      w5->SetState(1, 0);
      w5->inputGateFlag4c = 1;
      w5->childHitTestFlag4d = 1;
      w5->frameStyle60 = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w5->contentInsets68.left = layoutRect.left;
      w5->contentInsets68.top = layoutRect.top;
      w5->contentInsets68.right = layoutRect.right;
      w5->contentInsets68.bottom = layoutRect.bottom;
      w5->SetPictureResourceIdAndRefresh(0x4e22, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDeluxeText* w6 = new TDeluxeText();
      g_pUiResourceContext = w6;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = w6;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(w6);
      offset[0] = 0x19c;
      offset[1] = 0xff;
      size[0] = 0xd2;
      size[1] = 0x82;
      w6->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      w6->controlTag = static_cast<int>(0x72657175 /* 'requ' */);
      w6->controlValue3c = 0;
      w6->SetEnabled(1, 0);
      w6->SetState(0, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x72657175 /* 'requ' */);
    {
      TStaticText* w7 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x7473686f /* 'tsho' */, w7, 0x33, 0x1be,
                              0x8a, 0x17, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7473686f /* 'tsho' */);
    {
      TStaticText* w9 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x74717569 /* 'tqui' */, w9, 0x1cb, 0x1bd,
                              0x8a, 0x17, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x74717569 /* 'tqui' */);
    {
      TDeluxeText* w11 = new TDeluxeText();
      RegisterUiResourceEntry(0x74657677 /* 'tevw' */, 0x7469746c /* 'titl' */, w11, 0x84, 6, 0x177,
                              0x25, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c /* 'titl' */);
    PopUiResourcePoolNode(0x6d61696e /* 'main' */);
    PopUiResourcePoolNode(0x62617365 /* 'base' */);
  } break;

  // Place-city dialog (event 0x3c6): 'wind'/'DLOG' window with the TCitySiteView
  // city-site panel and an okay button.
  case 0x3c6: {
    {
      TWindow* w1 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, 0x57494e44 /* 'WIND' */, w1, 0xa0, 0x8a,
                              0x148, 0xaf, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* w3 = new TPicture();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x444c4f47 /* 'DLOG' */, w3, 0, 0, 0x14a,
                              0xaf, 0, 1, 0x57494e44, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x11bd);
      ClearUiResourceContext();
    }
    {
      TStaticText* w5 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x71756573 /* 'ques' */, w5, 0xc, 0xe, 0x12d,
                              0x21, 0, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x71756573 /* 'ques' */);
    {
      TRadioTextCluster* w7 = new TRadioTextCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x666f726d /* 'form' */, w7, 0x12, 0x34,
                              0x122, 0x55, 0, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x666f726d /* 'form' */);
    {
      TUpDownPictureButton* w9 = new TUpDownPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6f6b6179 /* 'okay' */, w9, 0xff, 0x8b,
                              0x3d, 0x18, 1, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179 /* 'okay' */);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  // Main-menu screen (event 0x5dc): a 2000x2000 'base' container holding a full-screen
  // 640x480 'main' TGameSetupPicture (bitmap 0x1194), seven 'cntl' TControl hotspots
  // (load/rand/mult/high/scen/quit/pref), and a 'tevw'/'curs' TInfoBarText info bar.
  case 0x5dc: {
    TView* base = new TView();
    RegisterUiResourceEntry(0x76696577, kControlTagBase, base, 0, 0, 0x7d0, 0x7d0, 0, 1, 0, 0);
    SetUiResourceStateFlags(1, 1);
    g_pUiResourceContext = 0;

    TGameSetupPicture* main = new TGameSetupPicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagMain, main, 0, 0, 0x280, 0x1e0, 0, 1,
                            kControlTagBase, 0);
    SetUiResourceStateFlags(1, 1);
    ReplaceUiResourceContextPairBuffer(0, 0xffffff);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1194);
    g_pUiResourceContext = 0;

    TControl* loadButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagLoad, loadButton, 0x3d, 0x6f, 0x89, 0x54, 1,
                            0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* randButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagRand, randButton, 0xe, 0xd1, 0x8a, 0xab, 1,
                            0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* multButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagMult, multButton, 0x1ca, 0x102, 0x8f, 0x8c,
                            1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* highButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagHigh, highButton, 0x1c0, 0x71, 0xa4, 0x4e,
                            1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* scenButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagScen, scenButton, 1, 0x18d, 0x9c, 0x48, 1,
                            0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TInfoBarText* cursorInfoText = new TInfoBarText();
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorInfoText, 0xb4, 0x1a8, 0x112,
                            0x34, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* quitButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagQuit, quitButton, 0xdd, 0x66, 0xc3, 0xc3, 1,
                            0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* prefButton = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagPref, prefButton, 0x21c, 0x18f, 0x64, 0x49,
                            1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
  } break;

  // GOLD dialog (event 0x3b9): a 'wind'/'WIND' captioned window hosting a 'pict'/'GOLD'
  // TPlaceCityDialog panel with title, okay/cancel buttons and two static labels.
  case 0x3b9: {
    {
      TWindow* w1 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, 0x57494e44 /* 'WIND' */, w1, 0xa0, 0x8a,
                              0x148, 0xaf, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPlaceCityDialog* w3 = new TPlaceCityDialog();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x444c4f47 /* 'DLOG' */, w3, 0, 0, 0x148,
                              0xaf, 0, 1, 0x57494e44, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24cc);
      ClearUiResourceContext();
    }
    {
      TStaticText* w5 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x7469746c /* 'titl' */, w5, 0x2e, 0x11,
                              0xee, 0x1a, 0, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 3, 1, 0xe, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c /* 'titl' */);
    {
      TUpDownPictureButton* w7 = new TUpDownPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6f6b6179 /* 'okay' */, w7, 0xff, 0x8e,
                              0x3d, 0x18, 1, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179 /* 'okay' */);
    {
      TUpDownPictureButton* w9 = new TUpDownPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x636e636c /* 'cncl' */, w9, 0xd, 0x8e, 0x3d,
                              0x17, 1, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c4);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x636e636c /* 'cncl' */);
    {
      TStaticText* w11 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x20202020 /* '    ' */, w11, 0x11, 0x5c,
                              0xa8, 0xe, 0, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 3, 0, 0, 0, -2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x20202020 /* '    ' */);
    {
      TStaticText* w13 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73757374 /* 'sust' */, w13, 0xe, 0x3b,
                              0x12b, 0x1d, 0, 1, 0x444c4f47, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 3, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73757374 /* 'sust' */);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  // Scenario-chooser screen (event 0x5e5): TScenarioChooser list panel with
  // selectable scenario titles and okay/cancel controls.
  case 0x5e5: {
    {
      TView* w1 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x62617365 /* 'base' */, w1, 0, 0, 0x7d0,
                              0x7d0, 0, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    {
      TGameSetupMultiplayerPicture* w3 = new TGameSetupMultiplayerPicture();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d61696e /* 'main' */, w3, 0, 0, 0x280,
                              0x1e0, 0, 1, 0x62617365, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x1068);
      ClearUiResourceContext();
    }
    {
      TControl* w5 = new TControl();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x6c6f6164 /* 'load' */, w5, 0x1d0, 0x50,
                              0x93, 0x56, 1, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c6f6164 /* 'load' */);
    {
      TControl* w7 = new TControl();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x72616e64 /* 'rand' */, w7, 0x1ba, 0xda,
                              0x8a, 0xab, 1, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x72616e64 /* 'rand' */);
    {
      TControl* w9 = new TControl();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x6d756c74 /* 'mult' */, w9, 0xc, 0x4f, 0x82,
                              0xba, 1, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6d756c74 /* 'mult' */);
    {
      TControl* w11 = new TControl();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x7363656e /* 'scen' */, w11, 0x128, 0x196,
                              0x9c, 0x48, 1, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7363656e /* 'scen' */);
    {
      TInfoBarText* w13 = new TInfoBarText();
      RegisterUiResourceEntry(0x74657677 /* 'tevw' */, 0x63757273 /* 'curs' */, w13, 0x22, 0x12,
                              0xe9, 0x21, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63757273 /* 'curs' */);
    {
      TDropShadowText* w15 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e616d65 /* 'name' */, w15, 0xf5, 0x17d,
                              0xa5, 0x13, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d65 /* 'name' */);
    {
      TRadioTextCluster* w17 = new TRadioTextCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x70726f74 /* 'prot' */, w17, 0xa3, 0x58,
                              0x100, 0xaf, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70726f74 /* 'prot' */);
    {
      TControl* w19 = new TControl();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x6a6f696e /* 'join' */, w19, 0x1d, 0x11a,
                              0xa0, 0x98, 1, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6a6f696e /* 'join' */);
    {
      TControl* w21 = new TControl();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x73706974 /* 'spit' */, w21, 0x186, 0x100,
                              0x21, 0x35, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73706974 /* 'spit' */);
    PopUiResourcePoolNode(0x6d61696e /* 'main' */);
    PopUiResourcePoolNode(0x62617365 /* 'base' */);
  } break;

  // New-game random-map setup screen (event 0x5dd): a 2000x2000 'base' container with a
  // 640x480 'main' TSetupRandomMapPicture (bitmap 0x11bc), a 'hot!' info bar, a right-hand
  // 'stuf' cluster (map preview, country title/flag/edit, OK button, difficulty + names
  // radio clusters), and 'key '/'auto'/'canc'/'cncl' hotspots, 'coat'/'glob' pictures.
  case 0x5dd: {
    TView* base = new TView();
    RegisterUiResourceEntry(0x76696577, kControlTagBase, base, 0, 0, 0x7d0, 0x7d0, 0, 1, 0, 0);
    SetUiResourceStateFlags(1, 1);
    g_pUiResourceContext = 0;

    TSetupRandomMapPicture* main = new TSetupRandomMapPicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagMain, main, 0, 0, 0x280, 0x1e0, 0, 1,
                            kControlTagBase, 0);
    SetUiResourceStateFlags(1, 1);
    ReplaceUiResourceContextPairBuffer(0, 0xffffff);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11bc);
    g_pUiResourceContext = 0;

    TInfoBarText* hotText = new TInfoBarText();
    RegisterUiResourceEntry(kControlTagTevw, kControlTagHot, hotText, 0x24, 0x16, 0xee, 0x1b, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TCluster* stuffCluster = new TCluster();
    RegisterUiResourceEntry(kControlTagClus, kControlTagStuf, stuffCluster, 0x120, 4, 0x159, 0x1d2,
                            0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    g_pUiResourceContext = 0;

    TMapPreviewView* mapPreview = new TMapPreviewView();
    RegisterUiResourceEntry(0x76696577, kControlTagMapP, mapPreview, 0xe, 0xa, 0x144, 0xb4, 0, 1,
                            kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* countryTitle = new TDropShadowText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagTcou, countryTitle, 0x42, 0xe6, 0x90, 0x10,
                            0, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TGWorldPartView* flagView = new TGWorldPartView();
    RegisterUiResourceEntry(0x76696577, kControlTagFlag, flagView, 0x19, 0xe1, 0x20, 0x18, 0, 1,
                            kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TEditText* countryEdit = new TEditText();
    RegisterUiResourceEntry(kControlTagEdit, kControlTagCoun, countryEdit, 0x17, 0xf9, 0x132, 0x16,
                            1, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 0);
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 0);
    SetUiResourceContextMaxCharCount(0x1e);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TUpDownPictureButton* okayButton = new TUpDownPictureButton();
    RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okayButton, 0x80, 0x1a2, 0x60, 0x1e,
                            1, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11a0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioTextCluster* difficultyCluster = new TRadioTextCluster();
    RegisterUiResourceEntry(kControlTagClus, kControlTagDiff, difficultyCluster, 0x19, 0x12a, 0x12e,
                            0x54, 0, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    g_pUiResourceContext = 0;

    TRadioText* difficulty0 = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagDif0, difficulty0, 2, 2, 0x12a, 0x10, 1, 1,
                            kControlTagDiff, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 0xc, g_szNewGameDifficultyIntroductory_00694A58, 0, 0, 0, 0,
                               1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioText* difficulty1 = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagDif1, difficulty1, 2, 0x12, 0x12a, 0x10, 1,
                            1, kControlTagDiff, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 0xd, g_szNewGameDifficultyEasy_00694A50, 0, 0, 0, 0, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioText* difficulty2 = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagDif2, difficulty2, 2, 0x22, 0x12a, 0x10, 1,
                            1, kControlTagDiff, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 0xe, g_szNewGameDifficultyNormal_00694A48, 0, 0, 0, 0, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioText* difficulty3 = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagDif3, difficulty3, 2, 0x32, 0x12a, 0x10, 1,
                            1, kControlTagDiff, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 0x11, g_szNewGameDifficultyHard_00694A40, 0, 0, 0, 0, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioText* difficulty4 = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagDif4, difficulty4, 2, 0x42, 0x12a, 0x10, 1,
                            1, kControlTagDiff, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 0x12, g_szNewGameDifficultyNighOnImpossible_00694A28, 0, 0, 0,
                               0, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();

    TDropShadowText* difficultyTitle = new TDropShadowText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagDift, difficultyTitle, 0x1a, 0x116, 0x9f,
                            0x12, 0, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 0x13, g_szNewGameDifficultySetting_00694A10, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TDropShadowText* namesTitle = new TDropShadowText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagTnam, namesTitle, 0x1a, 0x188, 0x3f, 0x10,
                            0, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 2, g_szNewGameNamesLabel_00694A08, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioTextCluster* namesCluster = new TRadioTextCluster();
    RegisterUiResourceEntry(kControlTagClus, kControlTagName, namesCluster, 0x5b, 0x186, 0xeb, 0x14,
                            0, 1, kControlTagStuf, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    g_pUiResourceContext = 0;

    TRadioText* namesHistorical = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagHist, namesHistorical, 2, 2, 0x73, 0x10, 1,
                            1, kControlTagName, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 7, g_szNewGameNamesHistorical_006949F8, 0, 0, 0, 0, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TRadioText* namesRandom = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagRand, namesRandom, 0x76, 2, 0x73, 0x10, 1,
                            1, kControlTagName, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 8, g_szNewGameNamesRandom_006949F0, 0, 0, 0, 0, 1);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();

    TControl* keyControl = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagKeyP, keyControl, 0x109, 0x119, 0xe, 0xe, 1,
                            0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TStaticText* autoLabel = new TStaticText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagAuto, autoLabel, 0xd9, 0x42, 0x41, 0x29, 0,
                            0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 1, g_szNewGameAllAutoGPs_006949E0, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* cancControl = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagCanc, cancControl, 0x2a, 0x37, 0x92, 0x4e,
                            1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TControl* cnclControl = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, kControlTagCncl, cnclControl, 0x2a, 0x85, 0x68, 0xea,
                            1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TPicture* coatPicture = new TPicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagCoat, coatPicture, 0xad, 0x14d, 0x46, 0x5e,
                            0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11cd);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();

    TNoHilitePicture* globePicture = new TNoHilitePicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagGlob, globePicture, 0x93, 0x86, 0x80, 0x80,
                            1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11d0);
    g_pUiResourceContext = 0;
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
  } break;

  // Strategic-map screen (event 0x3b8): full-screen 'base'/'main' tree with the
  // TMapUberPicture map surface, map key, toolbar cluster and info-bar texts.
  case 0x3b8: {
    {
      TView* w1 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x62617365 /* 'base' */, w1, 0, 0, 0x7d0,
                              0x7d0, 0, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    {
      TMapUberPicture* w3 = new TMapUberPicture();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d61696e /* 'main' */, w3, 0, 0, 0x280,
                              0x1e0, 0, 1, 0x62617365, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x3f8);
      ClearUiResourceContext();
    }
    {
      TToolBarCluster* w5 = new TToolBarCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x746f6f6c /* 'tool' */, w5, 0x205, 0, 0x7b,
                              0x1e0, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }
    {
      TPictureButton* w7 = new TPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x71756572 /* 'quer' */, w7, 0x5b, 8, 0x1a,
                              0x24, 1, 0, 0x746f6f6c, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x3f9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x71756572 /* 'quer' */);
    {
      TPictureButton* w9 = new TPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x63616e63 /* 'canc' */, w9, 4, 8, 0x53,
                              0x24, 1, 0, 0x746f6f6c, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x3fa);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63616e63 /* 'canc' */);
    PopUiResourcePoolNode(0x746f6f6c /* 'tool' */);
    {
      TCitySiteView* w11 = new TCitySiteView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x444c4f47 /* 'DLOG' */, w11, 5, 0x1b, 0x200,
                              0x1c0, 1, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    {
      TUpDownPictureButton* w13 = new TUpDownPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x73656e64 /* 'send' */, w13, 0xdc, 0xa,
                              0x13, 0xb, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24f1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73656e64 /* 'send' */);
    {
      TInfoBarText* w15 = new TInfoBarText();
      RegisterUiResourceEntry(0x74657677 /* 'tevw' */, 0x63757273 /* 'curs' */, w15, 0xf0, 5, 0x113,
                              0x15, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63757273 /* 'curs' */);
    PopUiResourcePoolNode(0x6d61696e /* 'main' */);
    PopUiResourcePoolNode(0x62617365 /* 'base' */);
  } break;

  // Multiplayer game-setup screen (event 0x5df): TGameSetupMultiplayerPicture panel,
  // per-player TCitySiteView slot, planet list and cursor info bar.
  case 0x5df: {
    {
      TView* w1 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x62617365 /* 'base' */, w1, 0, 0, 0x7d0,
                              0x7d0, 0, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    {
      TScenarioChooser* w3 = new TScenarioChooser();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d61696e /* 'main' */, w3, 0, 0, 0x280,
                              0x1e0, 0, 1, 0x62617365, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x1197);
      ClearUiResourceContext();
    }
    {
      TMapPreviewView* w5 = new TMapPreviewView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x706d6170 /* 'pmap' */, w5, 0x12e, 0xe,
                              0x144, 0xb4, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x706d6170 /* 'pmap' */);
    {
      TUpDownPictureButton* w7 = new TUpDownPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x73746172 /* 'star' */, w7, 0x1a0, 0x1a6,
                              0x60, 0x1e, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x11a0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73746172 /* 'star' */);
    {
      TDeluxeText* w9 = new TDeluxeText();
      RegisterUiResourceEntry(0x74657677 /* 'tevw' */, 0x63646573 /* 'cdes' */, w9, 0x135, 0xe6,
                              0x136, 0xb9, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63646573 /* 'cdes' */);
    {
      TDeluxeText* w11 = new TDeluxeText();
      RegisterUiResourceEntry(0x74657677 /* 'tevw' */, 0x73646573 /* 'sdes' */, w11, 0x30, 0xe6,
                              0xe4, 0xde, 0, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73646573 /* 'sdes' */);
    {
      TTextList* w13 = new TTextList();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x6c697374 /* 'list' */, w13, 0x27, 0x3d,
                              0xf4, 0x6e, 1, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c697374 /* 'list' */);
    {
      TClickZone* w15 = new TClickZone();
      RegisterUiResourceEntry(0x636e746c /* 'cntl' */, 0x65786974 /* 'exit' */, w15, 0, 0x3e, 0x25,
                              0xf0, 1, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x65786974 /* 'exit' */);
    {
      TInfoBarText* w17 = new TInfoBarText();
      RegisterUiResourceEntry(0x74657677 /* 'tevw' */, 0x63757273 /* 'curs' */, w17, 0x32, 0x11,
                              0xd6, 0x1e, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63757273 /* 'curs' */);
    {
      TDropShadowText* w19 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6d6f7265 /* 'more' */, w19, 0x28, 0xb0,
                              0xf2, 0x14, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6d6f7265 /* 'more' */);
    PopUiResourcePoolNode(0x6d61696e /* 'main' */);
    PopUiResourcePoolNode(0x62617365 /* 'base' */);
  } break;

  // Main statistics scoreboard screen (event 0x5eb): TGameScorePicture panel with the
  // per-nation stat text grid and a 'done' button.
  case 0x5eb: {
    {
      TView* w1 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x62617365 /* 'base' */, w1, 0, 0, 0x7d0,
                              0x7d0, 0, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    {
      TGameScorePicture* w3 = new TGameScorePicture();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x6d61696e /* 'main' */, w3, 0, 0, 0x280,
                              0x1e0, 1, 1, 0x62617365, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x11f3);
      ClearUiResourceContext();
    }
    {
      TDropShadowText* w5 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637261 /* 'scra' */, w5, 0x76, 0xa5,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637261 /* 'scra' */);
    {
      TDropShadowText* w7 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637262 /* 'scrb' */, w7, 0x76, 0xdb,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637262 /* 'scrb' */);
    {
      TDropShadowText* w9 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637263 /* 'scrc' */, w9, 0x76, 0x111,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637263 /* 'scrc' */);
    {
      TDropShadowText* w11 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637264 /* 'scrd' */, w11, 0x76, 0x135,
                              0x78, 0x30, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637264 /* 'scrd' */);
    {
      TDropShadowText* w13 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637265 /* 'scre' */, w13, 0x1a0, 0xa5,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637265 /* 'scre' */);
    {
      TDropShadowText* w15 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637266 /* 'scrf' */, w15, 0x1a0, 0xdb,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637266 /* 'scrf' */);
    {
      TDropShadowText* w17 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637267 /* 'scrg' */, w17, 0x1a0, 0x109,
                              0x78, 0x20, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637267 /* 'scrg' */);
    {
      TDropShadowText* w19 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637268 /* 'scrh' */, w19, 0x1a0, 0x149,
                              0x78, 0x20, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637268 /* 'scrh' */);
    {
      TDropShadowText* w21 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x73637269 /* 'scri' */, w21, 0x76, 0x17f,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73637269 /* 'scri' */);
    {
      TDropShadowText* w23 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x7363726a /* 'scrj' */, w23, 0x158, 0x17d,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7363726a /* 'scrj' */);
    {
      TDropShadowText* w25 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x7363726b /* 'scrk' */, w25, 0x158, 0x196,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7363726b /* 'scrk' */);
    {
      TDropShadowText* w27 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x7363726c /* 'scrl' */, w27, 0x15a, 0x1b8,
                              0x78, 0x18, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7363726c /* 'scrl' */);
    {
      TDropShadowText* w29 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d61 /* 'numa' */, w29, 0xe9, 0xa5,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d61 /* 'numa' */);
    {
      TDropShadowText* w31 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d62 /* 'numb' */, w31, 0xe9, 0xdb,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d62 /* 'numb' */);
    {
      TDropShadowText* w33 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d63 /* 'numc' */, w33, 0xe9, 0x111,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d63 /* 'numc' */);
    {
      TDropShadowText* w35 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d64 /* 'numd' */, w35, 0xea, 0x145,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d64 /* 'numd' */);
    {
      TDropShadowText* w37 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d69 /* 'numi' */, w37, 0xe9, 0x17f,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d69 /* 'numi' */);
    {
      TDropShadowText* w39 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d65 /* 'nume' */, w39, 0x213, 0xa5,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d65 /* 'nume' */);
    {
      TDropShadowText* w41 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d66 /* 'numf' */, w41, 0x213, 0xdb,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d66 /* 'numf' */);
    {
      TDropShadowText* w43 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d67 /* 'numg' */, w43, 0x213, 0x111,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d67 /* 'numg' */);
    {
      TDropShadowText* w45 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d68 /* 'numh' */, w45, 0x213, 0x151,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d68 /* 'numh' */);
    {
      TDropShadowText* w47 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d6a /* 'numj' */, w47, 0x213, 0x17d,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6a /* 'numj' */);
    {
      TDropShadowText* w49 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d6b /* 'numk' */, w49, 0x214, 0x195,
                              0x49, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6b /* 'numk' */);
    {
      TDropShadowText* w51 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6e756d6c /* 'numl' */, w51, 0x214, 0x1b8,
                              0x49, 0x18, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6c /* 'numl' */);
    {
      TDropShadowText* w53 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x76696374 /* 'vict' */, w53, 0x82, 0x2c,
                              0x18c, 0x48, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x76696374 /* 'vict' */);
    {
      TDropShadowText* w55 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x70746672 /* 'ptfr' */, w55, 0x76, 0x7f,
                              0x78, 0x10, 0, 1, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x514, 3, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70746672 /* 'ptfr' */);
    {
      TPictureButton* w57 = new TPictureButton();
      RegisterUiResourceEntry(0x70696374 /* 'pict' */, 0x646f6e65 /* 'done' */, w57, 7, 0x26, 0x1f,
                              0x34, 1, 0, 0x6d61696e, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x11f4);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x646f6e65 /* 'done' */);
    PopUiResourcePoolNode(0x6d61696e /* 'main' */);
    PopUiResourcePoolNode(0x62617365 /* 'base' */);
  } break;

  default:
    return 0;
  }

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
