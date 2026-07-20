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

// Board-of-Trade screen (events 0x7d9/0x7da): a 2000x2000 'base' container holding
// the 640x480 trade-board background, the tbr2 toolbar, seventeen commodity rows
// (gd*/rs*/ma* clusters with Sell/Avai number texts, card/offr order pictures,
// left/rght arrows, gree slider + bar amount bar), the Board-of-Trade book panel
// with its column labels, and the curs info bar. Case 0x7d9 opens with three
// expanded-idiom widgets; everything else speaks the compact helper vocabulary
// (heuristics note 36). Drafted from the original listing via `just gen-builder`.
// FUNCTION: IMPERIALISM 0x004601b0
TView* __cdecl InitializeTradeScreenBitmapControls(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  switch (static_cast<short>(nEventCode)) {
  case 0x7d9: {
    // 'base' root container: 2000x2000 logical layout area (expanded idiom, like
    // BuildStartupIntroBackground - the first three widgets of this case predate the
    // compact helper vocabulary in the original TU).
    {
      TView* base = new TView();
      g_pUiResourceContext = base;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = base;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(base);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x7d0;
      size[1] = 0x7d0;
      base->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      base->controlTag = static_cast<int>(kControlTagBase);
      base->controlValue3c = 0;
      base->SetEnabled(1, 0);
      base->SetState(0, 0);
      base->inputGateFlag4c = 1;
      base->childHitTestFlag4d = 1;
      g_pUiResourceContext = 0;
    }

    // 'main' 640x480 trade-board background (bitmap 0x835).
    {
      TTradeScreenPicture* main = new TTradeScreenPicture();
      g_pUiResourceContext = main;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = main;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(main);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x280;
      size[1] = 0x1e0;
      main->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      main->controlTag = static_cast<int>(kControlTagMain);
      main->controlValue3c = 0;
      main->SetEnabled(1, 0);
      main->SetState(0, 0);
      main->inputGateFlag4c = 1;
      main->childHitTestFlag4d = 1;
      // Inline ReplaceUiResourceContextPairBuffer(0, 0xffffff): the original writes
      // through the fresh stylePayload48 without a null re-check - faithful.
      delete main->stylePayload48;
      main->stylePayload48 = new TUiStyleBytes();
      main->stylePayload48->styleWord = 0;
      main->stylePayload48->packedColor = 0xffffff;
      main->frameStyle60 = 0xa;
      CRect zeroRect(0, 0, 0, 0);
      main->contentInsets68.left = zeroRect.left;
      main->contentInsets68.top = zeroRect.top;
      main->contentInsets68.right = zeroRect.right;
      main->contentInsets68.bottom = zeroRect.bottom;
      main->SetPictureResourceIdAndRefresh(0x835, 0);
      g_pUiResourceContext = 0;
    }

    // 'tbr2' toolbar cluster (expanded idiom).
    {
      TToolBarCluster* toolbar = new TToolBarCluster();
      g_pUiResourceContext = toolbar;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = toolbar;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(toolbar);
      offset[0] = 0x258;
      offset[1] = 0x1f;
      size[0] = 0x1e;
      size[1] = 0x2c;
      toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      toolbar->controlTag = static_cast<int>(kControlTagTbr2);
      toolbar->controlValue3c = 0;
      toolbar->SetEnabled(1, 0);
      toolbar->SetState(0, 0);
      toolbar->inputGateFlag4c = 1;
      toolbar->childHitTestFlag4d = 1;
      toolbar->frameStyle60 = 5;
      CRect zeroRect(0, 0, 0, 0);
      toolbar->contentInsets68.left = zeroRect.left;
      toolbar->contentInsets68.top = zeroRect.top;
      toolbar->contentInsets68.right = zeroRect.right;
      toolbar->contentInsets68.bottom = zeroRect.bottom;
      toolbar->field84 = 0x20202020; // '    '
      g_pUiResourceContext = 0;
    }

    {
      TPictureButton* quer_4 = new TPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagQuer, quer_4, 0, 2, 0x1b, 0x25, 1, 0,
                              0x74627232 /* 'tbr2' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x1784, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TPicture* cott_5 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f7474 /* 'cott' */, cott_5, 5, 0x95, 0x2a, 0x18,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x526, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* wool_6 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x776f6f6c /* 'wool' */, wool_6, 5, 0xbf, 0x2a, 0x18,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x527, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* food_7 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, kSummaryTagFood, food_7, 0x251, 0xbd, 0x2a, 0x18, 0,
                              1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52c, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TView* mpic_8 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x6d506963 /* 'mPic' */, mpic_8, 0x254, 0x6a,
                              0x23, 0x1a, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TToolBarCluster* tool_9 = new TToolBarCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, kControlTagTool, tool_9, 7, 6, 0xe4, 0x43, 0,
                              1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TPictureButton* end_10 = new TPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagEnd, end_10, 5, 0x1b, 0x1b, 0x25, 1, 0,
                              kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x1785, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* seas_11 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagSeas, seas_11, 0x2c, 4, 0x5e,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* trea_12 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagTrea, trea_12, 0x8d, 4, 0x4b,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TDropShadowNumberText* mcap_13 = new TDropShadowNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6d436170 /* 'mCap' */, mcap_13, 0x252,
                              0x88, 0x28, 0xe, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 0, 0, 0);
      BindUiResourceTextAndStyle(0x7d9, 1, g_szUiPlaceholder185_00694ABC, 0x15, 1, 0xc, 0, 1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0xb9, 0, 0x270f);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd0_14 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643020 /* 'gd0 ' */, gd0_14, 0x33, 0x62,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_15 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_15, 0x156, 3, 0x21,
                              0xf, 0, 0, 0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_16 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_16, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_17 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_17, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x850, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_18 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_18, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_19 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_19, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_20 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_20, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_21 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_21, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd1_22 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643120 /* 'gd1 ' */, gd1_22, 0x33, 0x76,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_23 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_23, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_24 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_24, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_25 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_25, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_26 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_26, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_27 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_27, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_28 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_28, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_29 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_29, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd2_30 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643220 /* 'gd2 ' */, gd2_30, 0x33, 0x8a,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_31 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_31, 0x158, 3, 0x1f,
                              0xf, 0, 0, 0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_32 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_32, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_33 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_33, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_34 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_34, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_35 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_35, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_36 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_36, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_37 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_37, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd3_38 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643320 /* 'gd3 ' */, gd3_38, 0x33, 0x9e,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_39 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_39, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_40 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_40, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_41 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_41, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_42 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_42, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_43 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_43, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_44 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_44, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_45 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_45, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma2_46 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613220 /* 'ma2 ' */, ma2_46, 0x33, 0xda,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_47 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_47, 0x158, 3, 0x1f,
                              0xf, 0, 0, 0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_48 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_48, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_49 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_49, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_50 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_50, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_51 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_51, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_52 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_52, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_53 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_53, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma3_54 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613320 /* 'ma3 ' */, ma3_54, 0x33, 0xee,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_55 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_55, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_56 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_56, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_57 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_57, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_58 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_58, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_59 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_59, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_60 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_60, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_61 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_61, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma1_62 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613120 /* 'ma1 ' */, ma1_62, 0x33, 0xc6,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_63 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_63, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_64 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_64, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_65 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_65, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_66 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_66, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_67 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_67, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_68 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_68, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_69 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_69, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma0_70 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613020 /* 'ma0 ' */, ma0_70, 0x33, 0xb2,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_71 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_71, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_72 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_72, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_73 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_73, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_74 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_74, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_75 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_75, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_76 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_76, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_77 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_77, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs5_78 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733520 /* 'rs5 ' */, rs5_78, 0x33, 0x17a,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_79 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_79, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_80 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_80, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_81 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_81, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_82 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_82, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_83 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_83, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_84 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_84, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_85 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_85, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs6_86 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733620 /* 'rs6 ' */, rs6_86, 0x33, 0x18e,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_87 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_87, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_88 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_88, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_89 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_89, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_90 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_90, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_91 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_91, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_92 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_92, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_93 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_93, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs4_94 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733420 /* 'rs4 ' */, rs4_94, 0x33, 0x166,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_95 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_95, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_96 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_96, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_97 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_97, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_98 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_98, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_99 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_99, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_100 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_100, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_101 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_101, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs3_102 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733320 /* 'rs3 ' */, rs3_102, 0x33,
                              0x152, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_103 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_103, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_104 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_104, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_105 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_105, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_106 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_106, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_107 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_107, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_108 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_108, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_109 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_109, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs2_110 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733220 /* 'rs2 ' */, rs2_110, 0x33,
                              0x13e, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_111 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_111, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_112 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_112, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_113 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_113, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_114 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_114, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_115 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_115, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_116 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_116, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_117 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_117, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs1_118 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733120 /* 'rs1 ' */, rs1_118, 0x33,
                              0x12a, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_119 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_119, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_120 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_120, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_121 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_121, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_122 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_122, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_123 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_123, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_124 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_124, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_125 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_125, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs0_126 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733020 /* 'rs0 ' */, rs0_126, 0x33,
                              0x116, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_127 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_127, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_128 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_128, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_129 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_129, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_130 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_130, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_131 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_131, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_132 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_132, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_133 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_133, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma4_134 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613420 /* 'ma4 ' */, ma4_134, 0x33,
                              0x102, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_135 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_135, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_136 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_136, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_137 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_137, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_138 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_138, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_139 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_139, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_140 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_140, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_141 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_141, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma5_142 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613520 /* 'ma5 ' */, ma5_142, 0x33,
                              0x1a2, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_143 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_143, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_144 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_144, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_145 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_145, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_146 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_146, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_147 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_147, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_148 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_148, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_149 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_149, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* topt_150 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x746f7054 /* 'topT' */, topt_150, 0x36,
                              0x25, 0x215, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 1, g_szUiBoardOfTradeLabel_00694AF8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* comt_151 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x636f6d54 /* 'comT' */, comt_151, 0x30,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 2, g_szUiCommodityLabel_00694AEC, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* ordt_152 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6f726454 /* 'ordT' */, ordt_152, 0x8a,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 3, g_szUiOrdersLabel_006948A4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* prit_153 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x70726954 /* 'priT' */, prit_153, 0xf0,
                              0x49, 0x43, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 4, g_szUiPriceLabel_00694AE4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* avat_154 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x61766154 /* 'avaT' */, avat_154, 0x136,
                              0x49, 0x48, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 5, g_szUiAvailableLabel_00694AD8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* qtyt_155 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x71747954 /* 'qtyT' */, qtyt_155, 0x182,
                              0x49, 0xb5, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiQuantityToOfferLabel_00694AC0, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TToolBarCluster* topb_156 = new TToolBarCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, kControlTagBpot, topb_156, 0x10b, 5, 0x69,
                              0x1a, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TUpDownPictureButton* tran_157 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagTran, tran_157, 3, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24ef, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* city_158 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCity, city_158, 0x1f, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24ed, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* trad_159 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagTrad, trad_159, 0x3b, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24eb, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* dipl_160 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagDipl, dipl_160, 0x58, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24e9, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TInfoBarText* curs_161 = new TInfoBarText();
      RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, curs_161, 0x182, 5, 0xc9, 0x1e, 0,
                              1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* timb_162 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x74696d62 /* 'timb' */, timb_162, 5, 0xe7, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x528, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* coal_163 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f616c /* 'coal' */, coal_163, 5, 0x110, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x529, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* iron_164 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x69726f6e /* 'iron' */, iron_164, 5, 0x13c, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52a, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* oil_165 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6f696c20 /* 'oil ' */, oil_165, 5, 0x164, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* fabr_166 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x66616272 /* 'fabr' */, fabr_166, 0x251, 0xe6, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52d, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* lumb_167 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6c756d62 /* 'lumb' */, lumb_167, 0x251, 0x112,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* stee_168 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x73746565 /* 'stee' */, stee_168, 0x251, 0x138,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52f, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    break;
  }
  case 0x7da: {
    {
      TView* base_1 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBase, base_1, 0, 0, 0x7d0, 0x7d0,
                              0, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    {
      TTradeScreenPicture* main_2 = new TTradeScreenPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagMain, main_2, 0, 0, 0x280, 0x1e0, 0, 1,
                              kControlTagBase, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x836, 0);
      g_pUiResourceContext = 0;
    }
    {
      TToolBarCluster* tbr2_3 = new TToolBarCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x74627232 /* 'tbr2' */, tbr2_3, 0x258, 0x1f,
                              0x1e, 0x2b, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TPictureButton* quer_4 = new TPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagQuer, quer_4, 0, 2, 0x1b, 0x25, 1, 0,
                              0x74627232 /* 'tbr2' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x1784, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd0_5 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643020 /* 'gd0 ' */, gd0_5, 0x33, 0x62,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_6 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_6, 0x156, 3, 0x21, 0xf,
                              0, 0, 0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_7 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_7, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_8 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_8, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x850, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_9 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_9, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_10 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_10, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_11 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_11, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_12 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_12, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd1_13 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643120 /* 'gd1 ' */, gd1_13, 0x33, 0x76,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_14 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_14, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_15 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_15, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_16 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_16, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_17 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_17, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_18 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_18, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_19 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_19, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_20 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_20, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd2_21 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643220 /* 'gd2 ' */, gd2_21, 0x33, 0x8a,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_22 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_22, 0x158, 3, 0x1f,
                              0xf, 0, 0, 0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_23 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_23, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_24 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_24, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_25 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_25, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_26 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_26, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_27 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_27, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_28 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_28, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* gd3_29 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x67643320 /* 'gd3 ' */, gd3_29, 0x33, 0x9e,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_30 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_30, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_31 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_31, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_32 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_32, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_33 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_33, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_34 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_34, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_35 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_35, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_36 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_36, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma2_37 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613220 /* 'ma2 ' */, ma2_37, 0x33, 0xda,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_38 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_38, 0x158, 3, 0x1f,
                              0xf, 0, 0, 0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_39 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_39, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_40 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_40, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_41 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_41, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_42 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_42, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_43 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_43, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_44 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_44, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma3_45 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613320 /* 'ma3 ' */, ma3_45, 0x33, 0xee,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_46 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_46, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_47 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_47, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_48 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_48, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_49 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_49, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_50 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_50, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_51 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_51, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_52 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_52, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma1_53 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613120 /* 'ma1 ' */, ma1_53, 0x33, 0xc6,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_54 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_54, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_55 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_55, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_56 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_56, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_57 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_57, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_58 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_58, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_59 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_59, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_60 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_60, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma0_61 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613020 /* 'ma0 ' */, ma0_61, 0x33, 0xb2,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_62 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_62, 0x157, 3, 0x20,
                              0xf, 0, 0, 0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_63 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_63, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_64 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_64, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_65 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_65, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_66 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_66, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_67 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_67, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_68 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_68, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs4_69 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733420 /* 'rs4 ' */, rs4_69, 0x33, 0x17a,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_70 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_70, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_71 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_71, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_72 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_72, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_73 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_73, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_74 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_74, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_75 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_75, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_76 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_76, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs5_77 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733520 /* 'rs5 ' */, rs5_77, 0x33, 0x18e,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_78 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_78, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_79 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_79, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_80 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_80, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_81 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_81, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_82 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_82, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_83 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_83, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_84 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_84, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs3_85 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733320 /* 'rs3 ' */, rs3_85, 0x33, 0x166,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_86 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_86, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_87 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_87, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_88 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_88, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_89 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_89, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_90 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_90, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_91 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_91, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_92 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_92, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs2_93 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733220 /* 'rs2 ' */, rs2_93, 0x33, 0x152,
                              0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_94 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_94, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_95 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_95, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_96 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_96, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_97 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_97, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_98 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_98, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_99 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_99, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_100 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_100, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs1_101 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733120 /* 'rs1 ' */, rs1_101, 0x33,
                              0x13e, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_102 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_102, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_103 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_103, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_104 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_104, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_105 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_105, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_106 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_106, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_107 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_107, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_108 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_108, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs0_109 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733020 /* 'rs0 ' */, rs0_109, 0x33,
                              0x12a, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_110 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_110, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_111 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_111, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_112 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_112, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_113 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_113, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_114 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_114, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_115 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_115, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_116 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_116, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma5_117 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613520 /* 'ma5 ' */, ma5_117, 0x33,
                              0x116, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_118 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_118, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_119 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_119, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_120 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_120, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_121 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_121, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_122 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_122, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_123 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_123, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_124 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_124, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* ma4_125 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x6d613420 /* 'ma4 ' */, ma4_125, 0x33,
                              0x102, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_126 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_126, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_127 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_127, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_128 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_128, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_129 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_129, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_130 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_130, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_131 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_131, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_132 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_132, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TTradeCluster* rs6_133 = new TTradeCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, 0x72733620 /* 'rs6 ' */, rs6_133, 0x33,
                              0x1a2, 0x207, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TMyNumberText* sell_134 = new TMyNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, kControlTagSell, sell_134, 0x14e, 3, 0x29,
                              0xf, 0, 0, 0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0xffffff, 0xffffff);
      SetUiResourceLayoutValues(6, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xfd, 1, g_szUiPlaceholderZero_00694378, 0x15, 1, 0xe, 0, -1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0x3e7);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* card_135 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_135, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTradeOrderPicture* offr_136 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_136, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* left_137 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_137, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSliderPicture* gree_138 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_138, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TSidewaysArrow* rght_139 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_139, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TTraderAmtBar* bar_140 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_140, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* topt_141 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x746f7054 /* 'topT' */, topt_141, 0x36,
                              0x25, 0x215, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 1, g_szUiBoardOfTradeLabel_00694AF8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* comt_142 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x636f6d54 /* 'comT' */, comt_142, 0x30,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 2, g_szUiCommodityLabel_00694AEC, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* ordt_143 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6f726454 /* 'ordT' */, ordt_143, 0x8a,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 3, g_szUiOrdersLabel_006948A4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* prit_144 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x70726954 /* 'priT' */, prit_144, 0xf0,
                              0x49, 0x43, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 4, g_szUiPriceLabel_00694AE4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* avat_145 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x61766154 /* 'avaT' */, avat_145, 0x136,
                              0x49, 0x48, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 5, g_szUiAvailableLabel_00694AD8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TStaticText* qtyt_146 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x71747954 /* 'qtyT' */, qtyt_146, 0x182,
                              0x49, 0xb5, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiQuantityToOfferLabel_00694AC0, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TToolBarCluster* tool_147 = new TToolBarCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, kControlTagTool, tool_147, 7, 6, 0xe4, 0x43,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TPictureButton* end_148 = new TPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagEnd, end_148, 5, 0x1b, 0x1b, 0x25, 1, 0,
                              kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x1785, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* seas_149 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagSeas, seas_149, 0x2c, 4, 0x5e,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowText* trea_150 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagTrea, trea_150, 0x8d, 4, 0x4b,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TView* mpic_151 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x6d506963 /* 'mPic' */, mpic_151, 0x254,
                              0x6a, 0x23, 0x1a, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TDropShadowNumberText* mcap_152 = new TDropShadowNumberText();
      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6d436170 /* 'mCap' */, mcap_152, 0x252,
                              0x88, 0x28, 0xe, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 0, 0, 0);
      BindUiResourceTextAndStyle(0x7d9, 1, g_szUiPlaceholder185_00694ABC, 0x15, 1, 0xc, 0, 1);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0xb9, 0, 0x270f);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* cott_153 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f7474 /* 'cott' */, cott_153, 5, 0x95, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x526, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* wool_154 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x776f6f6c /* 'wool' */, wool_154, 5, 0xbf, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x527, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* food_155 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, kSummaryTagFood, food_155, 0x251, 0xbd, 0x2a, 0x18,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52c, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* timb_156 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x74696d62 /* 'timb' */, timb_156, 5, 0xe7, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x528, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* coal_157 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f616c /* 'coal' */, coal_157, 5, 0x110, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x529, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* iron_158 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x69726f6e /* 'iron' */, iron_158, 5, 0x13c, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52a, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* oil_159 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6f696c20 /* 'oil ' */, oil_159, 5, 0x164, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52b, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* fabr_160 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x66616272 /* 'fabr' */, fabr_160, 0x251, 0xe6, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52d, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* lumb_161 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6c756d62 /* 'lumb' */, lumb_161, 0x251, 0x112,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52e, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TPicture* stee_162 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x73746565 /* 'stee' */, stee_162, 0x251, 0x138,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52f, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TToolBarCluster* topb_163 = new TToolBarCluster();
      RegisterUiResourceEntry(0x636c7573 /* 'clus' */, kControlTagBpot, topb_163, 0x10b, 5, 0x69,
                              0x1a, 0, 1, kControlTagBase, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      static_cast<TCluster*>(g_pUiResourceContext)->field84 =
          static_cast<int>(0x20202020 /* '    ' */);
      g_pUiResourceContext = 0;
    }
    {
      TUpDownPictureButton* tran_164 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagTran, tran_164, 3, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24ef, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* city_165 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCity, city_165, 0x1f, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24ed, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* trad_166 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagTrad, trad_166, 0x3b, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24eb, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    {
      TUpDownPictureButton* dipl_167 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagDipl, dipl_167, 0x58, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24e9, 0);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();
    {
      TInfoBarText* curs_168 = new TInfoBarText();
      RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, curs_168, 0x182, 5, 0xc9, 0x1e, 0,
                              1, kControlTagBase, 0);
      SetUiResourceStateFlags(1, 0);
      g_pUiResourceContext = 0;
    }
    break;
  }
  default:
    return 0;
  }

  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
