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

// FUNCTION: IMPERIALISM 0x0043dbc0
TView* __cdecl InitializeArmyNavyReportViewsAndCommandTags(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  switch (static_cast<short>(nEventCode)) {
  case 0x546: {

    {
      TWindow* wind_1 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_1, 0x17, 0x2a, 0xe6,
                              0x168, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }

    {
      TCombatReportView* gold_2 = new TCombatReportView();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, gold_2, 0, 0, 0xe6, 0x168, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    {
      TUpDownPictureButton* next_1 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x6e657874 /* 'next' */, next_1, 0x9d, 0x14f, 0x45,
                              0x13, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e657874);
    {
      TUpDownPictureButton* end_2 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagEnd, end_2, 3, 0x150, 0x45, 0x13, 1, 1,
                              kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x656e6420);
    {
      TPicture* pgdn_3 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, 0x706f7274 /* 'port' */, pgdn_3, 4, 4, 0xde, 0x97, 0,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x706f7274);

    {
      TColorKeyPicture* pgup_3 = new TColorKeyPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x70677570 /* 'pgup' */, pgup_3, 4, 0x136, 0x18,
                              0x14, 1, 0, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70677570);

    {
      TColorKeyPicture* pgdn_4 = new TColorKeyPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x7067646e /* 'pgdn' */, pgdn_4, 0xca, 0x136, 0x17,
                              0x14, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7067646e);
    {
      TStaticText* page_4 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x70616765 /* 'page' */, page_4, 0x44, 0x139, 0x5a,
                              0x10, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 1, g_szUiPage14of14_006949AC, 3, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70616765);
    {
      TStaticText* titl_5 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7469746c /* 'titl' */, titl_5, 6, 0xa4, 0xd9, 0x17,
                              0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 2, g_szUiSkirmishReportTitle_00694998, 3, 4, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c);
    {
      TStaticText* repo_6 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7265706f /* 'repo' */, repo_6, 7, 0xbf, 0xd6, 0x3e,
                              0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 3, g_szUiHaxacoLegions_0069494C, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7265706f);
    {
      TStaticText* orde_7 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6f726465 /* 'orde' */, orde_7, 0x35, 0x12a, 0x77,
                              0xe, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 4, g_szUiOrderOfBattle_00694930, 3, 0, 9, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f726465);
    {
      TStaticText* loss_8 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c6f7373 /* 'loss' */, loss_8, 0x39, 0xfe, 0x70,
                              0x2a, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 5, g_szUiLossesHaxaco_00694904, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c6f7373);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x7dd: {
    {
      TView* doog_9 = new TView();

      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBase, doog_9, 0, 0, 0x7d0, 0x7d0,
                              0, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }

    {
      TMapUberPicture* main_5 = new TMapUberPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagMain, main_5, 0, 0, 0x280, 0x1e0, 0, 1,
                              kControlTagBase, 0);
      SetUiResourceStateFlags(1, 1);
      ReplaceUiResourceContextPairBuffer(0, 0xffffff);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x407);
      ClearUiResourceContext();
    }

    {
      TMapDialog* gold_6 = new TMapDialog();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagGold, gold_6, 5, 0x1b, 0x200,
                              0x1c0, 1, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x444c4f47);

    {
      TOceanDialog* doog_7 = new TOceanDialog();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x444f4f47 /* 'DOOG' */, doog_7, 0x3e9, 0x1b,
                              0x200, 0x1c0, 1, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x444f4f47);
    {
      TToolBarCluster* tool_10 = new TToolBarCluster();

      RegisterUiResourceEntry(kControlTagClus, kControlTagTool, tool_10, 0x205, 0, 0x7b, 0x1e0, 0,
                              1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }
    {
      TPictureButton* flag_11 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x466c6167 /* 'Flag' */, flag_11, 0x3e, 8, 0x19,
                              0x23, 1, 0, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x514);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x466c6167);
    {
      TUpDownPictureButton* mmap_12 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x6d6d6170 /* 'mmap' */, mmap_12, 0x21, 8, 0x19,
                              0x23, 1, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x419);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6d6d6170);
    {
      TPictureButton* quer_13 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagQuer, quer_13, 0x5b, 8, 0x19, 0x23, 1, 0,
                              kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x51b);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x71756572);
    {
      TUpDownPictureButton* trad_14 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagTrad, trad_14, 0x3e, 0x77, 0x19, 0x19, 1,
                              1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x455);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x74726164);
    {
      TUpDownPictureButton* tran_15 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagTran, tran_15, 4, 0x77, 0x19, 0x19, 1, 1,
                              kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x457);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7472616e);
    {
      TUpDownPictureButton* city_16 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagCity, city_16, 0x21, 0x77, 0x19, 0x19, 1,
                              1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x456);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63697479);
    {
      TUpDownPictureButton* back_17 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagDipl, back_17, 0x5b, 0x77, 0x19, 0x19, 1,
                              1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x454);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6469706c);

    {
      TNavyToolbarCluster* unav_8 = new TNavyToolbarCluster();
      RegisterUiResourceEntry(kControlTagClus, 0x756e6176 /* 'unav' */, unav_8, 0x80, 0x90, 0x7b,
                              0x134, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TNoHilitePicture* back_9 = new TNoHilitePicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6261636b /* 'back' */, back_9, 4, 0x22, 0x70,
                              0x10d, 0, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x5fe);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6261636b);
    {
      TUpDownPictureButton* dfnd_18 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagDefend, dfnd_18, 0x5b, 9, 0x19, 0x19, 1, 1,
                              0x756e6176 /* 'unav' */, 0x41d);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x64666e64);
    {
      TUpDownPictureButton* done_19 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagDone, done_19, 0x3e, 9, 0x19, 0x19, 1, 1,
                              0x756e6176 /* 'unav' */, 0x41f);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b3);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x646f6e65);
    {
      TUpDownPictureButton* bomb_20 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x626f6d62 /* 'bomb' */, bomb_20, 4, 9, 0x19, 0x19,
                              1, 1, 0x756e6176 /* 'unav' */, 0x41f);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b5);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x626f6d62);
    {
      TUpDownPictureButton* arr9_21 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x6e657874 /* 'next' */, arr9_21, 0x21, 9, 0x19,
                              0x19, 1, 1, 0x756e6176 /* 'unav' */, 0x421);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4af);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e657874);

    {
      TShipFractionCluster* cls0_10 = new TShipFractionCluster();
      RegisterUiResourceEntry(kControlTagClus, 0x636c7330 /* 'cls0' */, cls0_10, 4, 0x48, 0x71,
                              0x39, 0, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TShipPlacard* ship_11 = new TShipPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x73686970 /* 'ship' */, ship_11, 0, 0, 0x64, 0x39,
                              0, 1, 0x636c7330 /* 'cls0' */, 0x425);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(4, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x5e9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73686970);

    {
      TNumberedArrowButton* arro_12 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x6172726f /* 'arro' */, arro_12, 0x64, 0, 0xb, 0x29,
                              1, 1, 0x636c7330 /* 'cls0' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6172726f);
    PopUiResourcePoolNode(0x636c7330);

    {
      TShipFractionCluster* cls1_13 = new TShipFractionCluster();
      RegisterUiResourceEntry(kControlTagClus, 0x636c7331 /* 'cls1' */, cls1_13, 4, 0x81, 0x71,
                              0x39, 0, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TShipPlacard* ship_14 = new TShipPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x73686970 /* 'ship' */, ship_14, 0, 0, 0x64, 0x39,
                              0, 1, 0x636c7331 /* 'cls1' */, 0x425);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(4, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x5e9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73686970);

    {
      TNumberedArrowButton* arro_15 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x6172726f /* 'arro' */, arro_15, 0x64, 0, 0xb, 0x29,
                              1, 1, 0x636c7331 /* 'cls1' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6172726f);
    PopUiResourcePoolNode(0x636c7331);

    {
      TShipFractionCluster* cls2_16 = new TShipFractionCluster();
      RegisterUiResourceEntry(kControlTagClus, 0x636c7332 /* 'cls2' */, cls2_16, 4, 0xbb, 0x71,
                              0x39, 0, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TShipPlacard* ship_17 = new TShipPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x73686970 /* 'ship' */, ship_17, 0, 0, 0x64, 0x39,
                              0, 1, 0x636c7332 /* 'cls2' */, 0x425);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(4, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x5e9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73686970);

    {
      TNumberedArrowButton* arro_18 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x6172726f /* 'arro' */, arro_18, 0x64, 0, 0xb, 0x29,
                              1, 1, 0x636c7332 /* 'cls2' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6172726f);
    PopUiResourcePoolNode(0x636c7332);

    {
      TShipFractionCluster* cls3_19 = new TShipFractionCluster();
      RegisterUiResourceEntry(kControlTagClus, 0x636c7333 /* 'cls3' */, cls3_19, 4, 0xf4, 0x71,
                              0x39, 0, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TShipPlacard* ship_20 = new TShipPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x73686970 /* 'ship' */, ship_20, 0, 0, 0x64, 0x39,
                              0, 1, 0x636c7333 /* 'cls3' */, 0x425);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(4, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x5e9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73686970);

    {
      TNumberedArrowButton* arro_21 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x6172726f /* 'arro' */, arro_21, 0x64, 0, 0xb, 0x29,
                              1, 1, 0x636c7333 /* 'cls3' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6172726f);
    PopUiResourcePoolNode(0x636c7333);

    {
      TRadioPictureButton* agr0_22 = new TRadioPictureButton();
      RegisterUiResourceEntry(kControlTagPict, 0x61677230 /* 'agr0' */, agr0_22, 4, 0x2b, 0x23,
                              0x19, 1, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x60e);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61677230);

    {
      TRadioPictureButton* agr1_23 = new TRadioPictureButton();
      RegisterUiResourceEntry(kControlTagPict, 0x61677231 /* 'agr1' */, agr1_23, 0x2b, 0x2b, 0x22,
                              0x19, 1, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x610);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61677231);

    {
      TRadioPictureButton* agr2_24 = new TRadioPictureButton();
      RegisterUiResourceEntry(kControlTagPict, 0x61677232 /* 'agr2' */, agr2_24, 0x51, 0x2b, 0x23,
                              0x19, 1, 1, 0x756e6176 /* 'unav' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x612);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61677232);
    PopUiResourcePoolNode(0x756e6176);

    {
      TArmyToolbar* uarm_25 = new TArmyToolbar();
      RegisterUiResourceEntry(kControlTagClus, 0x7561726d /* 'uarm' */, uarm_25, 0x80, 0x92, 0x78,
                              0x133, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TNumberedArrowButton* w_26 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, kTagArmyRatioMin, w_26, 0x2e, 0x24, 0xb, 0x29, 1, 1,
                              0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727230);

    {
      TNumberedArrowButton* arr1_27 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727231 /* 'arr1' */, arr1_27, 0x2e, 0x59, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727231);

    {
      TNumberedArrowButton* arr2_28 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727232 /* 'arr2' */, arr2_28, 0x2e, 0x8e, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727232);

    {
      TNumberedArrowButton* arr3_29 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727233 /* 'arr3' */, arr3_29, 0x2e, 0xc3, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727233);

    {
      TNumberedArrowButton* arr4_30 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727234 /* 'arr4' */, arr4_30, 0x68, 0x24, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727234);

    {
      TNumberedArrowButton* arr5_31 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727235 /* 'arr5' */, arr5_31, 0x68, 0x59, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727235);

    {
      TNumberedArrowButton* arr6_32 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727236 /* 'arr6' */, arr6_32, 0x68, 0x8e, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727236);

    {
      TNumberedArrowButton* arr7_33 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727237 /* 'arr7' */, arr7_33, 0x68, 0xc3, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727237);

    {
      TNumberedArrowButton* arr8_34 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, 0x61727238 /* 'arr8' */, arr8_34, 0x2e, 0xf8, 0xb,
                              0x29, 1, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727238);

    {
      TNumberedArrowButton* w_35 = new TNumberedArrowButton();
      RegisterUiResourceEntry(kControlTagCntl, kTagArmyRatioMax, w_35, 0x68, 0xf8, 0xb, 0x29, 1, 1,
                              0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x61727239);
    {
      TUpDownPictureButton* dfnd_22 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagDefend, dfnd_22, 0x5b, 7, 0x19, 0x19, 1, 1,
                              0x7561726d /* 'uarm' */, 0x41d);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x64666e64);
    {
      TUpDownPictureButton* done_23 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagDone, done_23, 0x3e, 7, 0x19, 0x19, 1, 1,
                              0x7561726d /* 'uarm' */, 0x41f);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b3);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x646f6e65);
    {
      TUpDownPictureButton* garr_24 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagGarrison, garr_24, 4, 7, 0x19, 0x19, 1, 1,
                              0x7561726d /* 'uarm' */, 0x41f);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b5);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x67617272);
    {
      TUpDownPictureButton* pic9_25 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagLater, pic9_25, 0x21, 7, 0x19, 0x19, 1, 1,
                              0x7561726d /* 'uarm' */, 0x421);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4af);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c617472);

    {
      TArmyPlacard* pic0_36 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696330 /* 'pic0' */, pic0_36, 4, 0x24, 0x2a,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4c4);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696330);

    {
      TArmyPlacard* pic1_37 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696331 /* 'pic1' */, pic1_37, 4, 0x59, 0x2a,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4c5);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696331);

    {
      TArmyPlacard* pic2_38 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696332 /* 'pic2' */, pic2_38, 4, 0x8e, 0x2a,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4c6);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696332);

    {
      TArmyPlacard* pic3_39 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696333 /* 'pic3' */, pic3_39, 4, 0xc3, 0x2a,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4c7);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696333);

    {
      TArmyPlacard* pic4_40 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696334 /* 'pic4' */, pic4_40, 0x39, 0x24, 0x2f,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4c8);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696334);

    {
      TArmyPlacard* pic5_41 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696335 /* 'pic5' */, pic5_41, 0x39, 0x59, 0x2f,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4c9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696335);

    {
      TArmyPlacard* pic6_42 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696336 /* 'pic6' */, pic6_42, 0x39, 0x8e, 0x2f,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4ca);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696336);

    {
      TArmyPlacard* pic7_43 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696337 /* 'pic7' */, pic7_43, 0x39, 0xc3, 0x2f,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4cb);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696337);

    {
      TArmyPlacard* pic8_44 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696338 /* 'pic8' */, pic8_44, 4, 0xf8, 0x2a,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4dc);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696338);

    {
      TArmyPlacard* pic9_45 = new TArmyPlacard();
      RegisterUiResourceEntry(kControlTagPict, 0x70696339 /* 'pic9' */, pic9_45, 0x39, 0xf8, 0x2f,
                              0x35, 0, 1, 0x7561726d /* 'uarm' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4df);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70696339);
    PopUiResourcePoolNode(0x7561726d);
    {
      TPictureButton* back_26 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x444f4e45 /* 'DONE' */, back_26, 4, 0x1c5, 0x70,
                              0x13, 1, 0, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x3f3);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x444f4e45);

    {
      TCivToolbar* uciv_46 = new TCivToolbar();
      RegisterUiResourceEntry(kControlTagClus, 0x75636976 /* 'uciv' */, uciv_46, 0x80, 0x8f, 0x7e,
                              0x132, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }

    {
      TNoHilitePicture* unit_47 = new TNoHilitePicture();
      RegisterUiResourceEntry(kControlTagPict, 0x756e6974 /* 'unit' */, unit_47, 0x21, 0x27, 0x36,
                              0x44, 0, 0, 0x75636976 /* 'uciv' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x438);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x756e6974);

    {
      TCivDescription* back_48 = new TCivDescription();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x6261636b /* 'back' */, back_48, 0, 0x27,
                              0x7b, 0x104, 0, 1, 0x75636976 /* 'uciv' */, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6261636b);
    {
      TUpDownPictureButton* dfnd_27 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagDefend, dfnd_27, 0x5b, 0xa, 0x19, 0x19, 1, 1,
                              0x75636976 /* 'uciv' */, 0x41d);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4bb);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x64666e64);
    {
      TUpDownPictureButton* done_28 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagDone, done_28, 0x3e, 0xa, 0x19, 0x19, 1, 1,
                              0x75636976 /* 'uciv' */, 0x41f);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b3);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x646f6e65);
    {
      TUpDownPictureButton* garr_29 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagGarrison, garr_29, 4, 0xa, 0x19, 0x19, 1, 1,
                              0x75636976 /* 'uciv' */, 0x41f);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4b9);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x67617272);
    {
      TUpDownPictureButton* latr_30 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kTagLater, latr_30, 0x21, 0xa, 0x19, 0x19, 1, 1,
                              0x75636976 /* 'uciv' */, 0x421);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x4af);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c617472);
    PopUiResourcePoolNode(0x75636976);
    {
      TCluster* ocea_31 = new TCluster();

      RegisterUiResourceEntry(kControlTagClus, 0x6f636561 /* 'ocea' */, ocea_31, 1, 5, 0x1d, 0x28,
                              0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }
    {
      TPictureButton* zmot_32 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x5a6d4f74 /* 'ZmOt' */, zmot_32, 3, 3, 0x19, 0x23,
                              1, 0, 0x6f636561 /* 'ocea' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x459);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x5a6d4f74);
    PopUiResourcePoolNode(0x6f636561);
    PopUiResourcePoolNode(0x746f6f6c);
    {
      TToolBarCluster* tbr1_33 = new TToolBarCluster();

      RegisterUiResourceEntry(kControlTagClus, kControlTagTrb1, tbr1_33, 3, 6, 0xb3, 0x13, 0, 1,
                              kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(5, 0, 0, 0, 0);
      SetUiResourceContextStringCode(0x20202020);
      ClearUiResourceContext();
    }
    {
      TDropShadowText* seas_34 = new TDropShadowText();

      RegisterUiResourceEntry(kControlTagStat, kControlTagSeas, seas_34, 2, 1, 0x5e, 0x11, 0, 1,
                              kControlTagTrb1, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 4, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73656173);
    {
      TDropShadowText* trea_35 = new TDropShadowText();

      RegisterUiResourceEntry(kControlTagStat, kControlTagTrea, trea_35, 0x63, 1, 0x4b, 0x11, 0, 1,
                              kControlTagTrb1, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 3, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x74726561);
    PopUiResourcePoolNode(0x74627231);
    {
      TInfoBarText* curs_36 = new TInfoBarText();

      RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, curs_36, 0xf0, 5, 0x113, 0x15, 0, 1,
                              kControlTagMain, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63757273);
    {
      TUpDownPictureButton* dlog_37 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x73656e64 /* 'send' */, dlog_37, 0xdc, 0xa, 0x13,
                              0xb, 0, 0, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24f1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73656e64);
    PopUiResourcePoolNode(0x6d61696e);
    PopUiResourcePoolNode(0x62617365 /* 'base' */);
  } break;

  case 0xbc4: {

    {
      TWindow* main_49 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagMain, main_49, 0xab, 0x87, 0x12c,
                              0xc8, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 1, 1);
      ClearUiResourceContext();
    }

    {
      TCivReport* gold_50 = new TCivReport();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, gold_50, 0, 0, 0x12c, 0xc8, 0, 1,
                              kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xbc4);
      ClearUiResourceContext();
    }
    {
      TStaticText* ttl0_38 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x74746c30 /* 'ttl0' */, ttl0_38, 0xd, 0xc, 0x116,
                              0x13, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x22, g_szUiCivilianReportTitle_006948F0, 3, 1, 0xe, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x74746c30);
    {
      TPictureButton* okay_39 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okay_39, 0xc6, 0x88, 0x3c, 0x23, 1,
                              0, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xbc6);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);
    {
      TPictureButton* info_40 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagCanc, info_40, 0x2e, 0x88, 0x3c, 0x23, 1,
                              0, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xbc5);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63616e63);

    {
      TDeluxeText* info_51 = new TDeluxeText();
      RegisterUiResourceEntry(kControlTagTevw, kControlTagInfo, info_51, 7, 0x2c, 0x11f, 0x5b, 0, 1,
                              kControlTagGold, 0);
      SetUiResourceStateFlags(1, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x696e666f);
    {
      TStaticText* ttl1_41 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x74746c31 /* 'ttl1' */, ttl1_41, 0xa, 0xad, 0x83,
                              0x11, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 9, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x74746c31);
    {
      TStaticText* ttl2_42 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x74746c32 /* 'ttl2' */, ttl2_42, 0xa4, 0xad, 0x82,
                              0x11, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 9, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x74746c32);
    PopUiResourcePoolNode(0x444c4f47);
    PopUiResourcePoolNode(0x6d61696e /* 'main' */);
  } break;

  case 0xc1c: {

    // Civilian-report screen (event 0xc1c): the first four widgets predate the compact
    // helper vocabulary in the original TU (expanded idiom, like the 2508 dialog).
    {
      TWindow* window = new TWindow();
      g_pUiResourceContext = window;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = window;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(window);
      int offset[2];
      int size[2];
      offset[0] = 0xa0;
      offset[1] = 0x8a;
      size[0] = 0x15e;
      size[1] = 0xfa;
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
      window->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020,
                                                                           0x20202020);
      g_pUiResourceContext = 0;
    }

    {
      TArmyInfoView* reportView = new TArmyInfoView();
      g_pUiResourceContext = reportView;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = reportView;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(reportView);
      int offset[2];
      int size[2];
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x15e;
      size[1] = 0xfa;
      reportView->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      reportView->controlTag = static_cast<int>(kControlTagGold);
      reportView->controlValue3c = 0;
      reportView->SetEnabled(1, 0);
      reportView->SetState(0, 0);
      reportView->inputGateFlag4c = 1;
      reportView->childHitTestFlag4d = 1;
      reportView->frameStyle60 = 0xa;
      CRect zeroRect(0, 0, 0, 0);
      reportView->contentInsets68.left = zeroRect.left;
      reportView->contentInsets68.top = zeroRect.top;
      reportView->contentInsets68.right = zeroRect.right;
      reportView->contentInsets68.bottom = zeroRect.bottom;
      reportView->SetPictureResourceIdAndRefresh(0x605, 0);
      g_pUiResourceContext = 0;
    }

    {
      TStaticText* titleText = new TStaticText();
      g_pUiResourceContext = titleText;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = titleText;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(titleText);
      int offset[2];
      int size[2];
      offset[0] = 0xc;
      offset[1] = 0x1b;
      size[0] = 0x146;
      size[1] = 0x17;
      titleText->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      titleText->controlTag = static_cast<int>(0x7469746c); // 'titl'
      titleText->controlValue3c = 0;
      titleText->SetEnabled(1, 0);
      titleText->SetState(0, 0);
      titleText->inputGateFlag4c = 1;
      titleText->childHitTestFlag4d = 1;
      titleText->frameStyle60 = 0xd;
      CRect zeroRect(0, 0, 0, 0);
      titleText->contentInsets68.left = zeroRect.left;
      titleText->contentInsets68.top = zeroRect.top;
      titleText->contentInsets68.right = zeroRect.right;
      titleText->contentInsets68.bottom = zeroRect.bottom;
      BindUiResourceTextAndStyle(0x5e5, 0x24, g_szUiArmyReportTitle_006948E0, 3, 1, 0x12, 0, 1);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();

    {
      TStaticText* whomText = new TStaticText();
      g_pUiResourceContext = whomText;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = whomText;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(whomText);
      int offset[2];
      int size[2];
      offset[0] = 0x10;
      offset[1] = 0x6b;
      size[0] = 0x96;
      size[1] = 0x57;
      whomText->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      whomText->controlTag = static_cast<int>(0x77686f6d); // 'whom'
      whomText->controlValue3c = 0;
      whomText->SetEnabled(1, 0);
      whomText->SetState(0, 0);
      whomText->inputGateFlag4c = 1;
      whomText->childHitTestFlag4d = 1;
      whomText->frameStyle60 = 0xd;
      CRect zeroRect(0, 0, 0, 0);
      whomText->contentInsets68.left = zeroRect.left;
      whomText->contentInsets68.top = zeroRect.top;
      whomText->contentInsets68.right = zeroRect.right;
      whomText->contentInsets68.bottom = zeroRect.bottom;
      BindUiResourceTextAndStyle(0x5e5, 0x12, g_szUiOneHenTwoDucks_006948AC, 3, 0, 0xc, 0, -2);
      g_pUiResourceContext = 0;
    }
    PopUiWidgetBuildStackNode();

    {
      TStaticText* lab3_45 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616233 /* 'lab3' */, lab3_45, 0xb8, 0x54, 0x92,
                              0x12, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xa, g_szUiOrdersLabel_006948A4, 3, 5, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616233);
    {
      TStaticText* ords_46 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6f726473 /* 'ords' */, ords_46, 0xc5, 0x6c, 0x85,
                              0x45, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x16, g_szUiPatrolTheWaters_0069487C, 3, 0, 0xc, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f726473);
    {
      TUpDownPictureButton* canc_47 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagCanc, canc_47, 0xbb, 0xd5, 0x3d, 0x17, 1,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c4);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63616e63);
    {
      TUpDownPictureButton* okay_48 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okay_48, 0x10c, 0xd5, 0x3d, 0x18, 1,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);
    {
      TStaticText* lab2_49 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616232 /* 'lab2' */, lab2_49, 0x11, 0x54, 0x92,
                              0x12, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xb, g_szUiCompositionLabel_0069486C, 3, 5, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616232);
    {
      TStaticText* rcor_50 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x67656e65 /* 'gene' */, rcor_50, 0xf, 0xc9, 0x97,
                              0x1b, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1e, g_szUiAdmiralBobMinnow_00694840, 3, 0, 0xa, 0, -2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x67656e65);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0xdac: {

    {
      TWindow* wind_52 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_52, 0x11, 0x33, 0x1e0,
                              0x190, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }

    {
      TBook* gold_53 = new TBook();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, gold_53, 0, 0, 0x1e0, 0x190, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdac);
      ClearUiResourceContext();
    }

    {
      TGarrisonView* page_54 = new TGarrisonView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x70616765 /* 'page' */, page_54, 0xd, 0x2e,
                              0x1ca, 0x136, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70616765);

    {
      TPageCorner* lcor_55 = new TPageCorner();
      RegisterUiResourceEntry(kControlTagPict, 0x6c636f72 /* 'lcor' */, lcor_55, 0xc, 0x164, 0x29,
                              0x24, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c636f72);

    {
      TPageCorner* rcor_56 = new TPageCorner();
      RegisterUiResourceEntry(kControlTagPict, 0x72636f72 /* 'rcor' */, rcor_56, 0x1af, 0x164, 0x29,
                              0x24, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x72636f72);
    {
      TPictureButton* wind_51 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, wind_51, 0x1c, 0xb, 0x1d, 0x1d, 1,
                              0, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb3);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0xdb4: {

    {
      TWindow* wind_57 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_57, 0xa0, 0x8a, 0x104,
                              0x64, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* dlog_52 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, dlog_52, 0, 0, 0x104, 0x64, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb4);
      ClearUiResourceContext();
    }
    {
      TUpDownPictureButton* cncl_53 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagCncl, cncl_53, 0x10, 0x44, 0x3d, 0x17, 1,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c4);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x636e636c);
    {
      TUpDownPictureButton* name_54 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, name_54, 0xb9, 0x43, 0x3d, 0x18, 1,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);

    {
      TEditText* name_58 = new TEditText();
      RegisterUiResourceEntry(kControlTagEdit, kControlTagName, name_58, 0x19, 0x23, 0xcc, 0x19, 1,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 0);
      ReplaceUiResourceContextPairBuffer(0x12286f, 0xa7f2ff);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(0x5e5, 0x15, g_szUiEditTextLabel_00694834, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0x10);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d65);
    {
      TStaticText* dlog_55 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7469746c /* 'titl' */, dlog_55, 0x1c, 0xc, 0xc9,
                              0xf, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 9, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c /* 'titl' */);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x1c20: {

    {
      TWindow* wind_59 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_59, 0x5e, 0x63, 0x148,
                              0x46, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }

    {
      TEngineerDialog* gold_60 = new TEngineerDialog();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagGold, gold_60, 0, 1, 0x148, 0x46,
                              0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    {
      TStaticText* wind_56 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7469746c /* 'titl' */, wind_56, 0x28, 4, 0xf0,
                              0x10, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x1c21, 1, g_szUiConstructionOptions_00694818, 3, 1, 0xe, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x24f4: {

    {
      TWindow* wind_61 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_61, 0xe, 0x3b, 0x258,
                              0x12c, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 1, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* w57 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, 0x20202020 /* '    ' */, w57, 0, 0, 0x258, 0x12c, 0,
                              1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24f5);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x20202020);
    {
      TNumberText* numa_58 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d61 /* 'numa' */, numa_58, 0x88, 0x15,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d61);
    {
      TStaticText* nama_59 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d61 /* 'nama' */, nama_59, 0xa, 0x18, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d61);
    {
      TStaticText* namb_60 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d62 /* 'namb' */, namb_60, 0xa, 0x2f, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 7, g_szUiSkirmishersLabel_006947FC, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d62);
    {
      TNumberText* numb_61 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d62 /* 'numb' */, numb_61, 0x88, 0x2c,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d62);
    {
      TStaticText* namc_62 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d63 /* 'namc' */, namc_62, 0xa, 0x46, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 8, g_szUiRegularsLabel_006947F0, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d63);
    {
      TNumberText* numc_63 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d63 /* 'numc' */, numc_63, 0x88, 0x43,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d63);
    {
      TNumberText* numd_64 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d64 /* 'numd' */, numd_64, 0x88, 0x5a,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d64);
    {
      TStaticText* namd_65 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d64 /* 'namd' */, namd_65, 0xa, 0x5d, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d64);
    {
      TStaticText* namg_66 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d67 /* 'namg' */, namg_66, 0xa, 0xa2, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d67);
    {
      TNumberText* numg_67 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d67 /* 'numg' */, numg_67, 0x88, 0x9f,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d67);
    {
      TNumberText* numh_68 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d68 /* 'numh' */, numh_68, 0x88, 0xb6,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d68);
    {
      TStaticText* namh_69 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d68 /* 'namh' */, namh_69, 0xa, 0xb9, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d68);
    {
      TStaticText* namf_70 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d66 /* 'namf' */, namf_70, 0xa, 0x8b, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d66);
    {
      TNumberText* numf_71 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d66 /* 'numf' */, numf_71, 0x88, 0x88,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d66);
    {
      TNumberText* nume_72 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d65 /* 'nume' */, nume_72, 0x88, 0x71,
                              0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d65);
    {
      TStaticText* name_73 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, kControlTagName, name_73, 0xa, 0x74, 0x6e, 0xf, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d65);
    {
      TStaticText* nami_74 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d69 /* 'nami' */, nami_74, 0xc0, 0x19, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d69);
    {
      TNumberText* numi_75 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d69 /* 'numi' */, numi_75, 0x13e,
                              0x16, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d69);
    {
      TNumberText* numj_76 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6a /* 'numj' */, numj_76, 0x13e,
                              0x2d, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6a);
    {
      TStaticText* namj_77 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6a /* 'namj' */, namj_77, 0xc0, 0x30, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6a);
    {
      TStaticText* namk_78 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6b /* 'namk' */, namk_78, 0xc0, 0x47, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6b);
    {
      TNumberText* numk_79 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6b /* 'numk' */, numk_79, 0x13e,
                              0x44, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6b);
    {
      TNumberText* numl_80 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6c /* 'numl' */, numl_80, 0x13e,
                              0x5b, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6c);
    {
      TStaticText* naml_81 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6c /* 'naml' */, naml_81, 0xc0, 0x5e, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6c);
    {
      TStaticText* namm_82 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6d /* 'namm' */, namm_82, 0xc0, 0x75, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6d);
    {
      TNumberText* numm_83 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6d /* 'numm' */, numm_83, 0x13e,
                              0x72, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6d);
    {
      TNumberText* numn_84 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6e /* 'numn' */, numn_84, 0x13e,
                              0x89, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6e);
    {
      TStaticText* namn_85 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6e /* 'namn' */, namn_85, 0xc0, 0x8c, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6e);
    {
      TStaticText* namo_86 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6f /* 'namo' */, namo_86, 0xc0, 0xa3, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6f);
    {
      TNumberText* numo_87 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6f /* 'numo' */, numo_87, 0x13e,
                              0xa0, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6f);
    {
      TNumberText* nump_88 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d70 /* 'nump' */, nump_88, 0x13e,
                              0xb7, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d70);
    {
      TStaticText* namp_89 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d70 /* 'namp' */, namp_89, 0xc0, 0xba, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d70);
    {
      TStaticText* namq_90 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d71 /* 'namq' */, namq_90, 0x16f, 0x19, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d71);
    {
      TNumberText* numq_91 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d71 /* 'numq' */, numq_91, 0x1ed,
                              0x16, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d71);
    {
      TNumberText* numr_92 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d72 /* 'numr' */, numr_92, 0x1ed,
                              0x2d, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d72);
    {
      TStaticText* namr_93 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d72 /* 'namr' */, namr_93, 0x16f, 0x30, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d72);
    {
      TStaticText* nams_94 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d73 /* 'nams' */, nams_94, 0x16f, 0x47, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d73);
    {
      TNumberText* nums_95 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d73 /* 'nums' */, nums_95, 0x1ed,
                              0x44, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d73);
    {
      TNumberText* numt_96 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d74 /* 'numt' */, numt_96, 0x1ed,
                              0x5b, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d74);
    {
      TStaticText* namt_97 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d74 /* 'namt' */, namt_97, 0x16f, 0x5e, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d74);
    {
      TStaticText* namu_98 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d75 /* 'namu' */, namu_98, 0x16f, 0x75, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d75);
    {
      TNumberText* numu_99 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d75 /* 'numu' */, numu_99, 0x1ed,
                              0x72, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d75);
    {
      TNumberText* numv_100 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d76 /* 'numv' */, numv_100, 0x1ed,
                              0x89, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d76);
    {
      TStaticText* namv_101 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d76 /* 'namv' */, namv_101, 0x16f, 0x8c, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d76);
    {
      TStaticText* namw_102 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d77 /* 'namw' */, namw_102, 0x16f, 0xa3, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d77);
    {
      TNumberText* numw_103 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d77 /* 'numw' */, numw_103, 0x1ed,
                              0xa0, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d77);
    {
      TNumberText* numy_104 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d79 /* 'numy' */, numy_104, 0x88,
                              0xcd, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d79);
    {
      TStaticText* namy_105 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d79 /* 'namy' */, namy_105, 0xa, 0xd0, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d79);
    {
      TUpDownPictureButton* w106 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x20202020 /* '    ' */, w106, 0x1c2, 0xef, 0x3d,
                              0x18, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x20202020);
    {
      TNumberText* numx_107 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d78 /* 'numx' */, numx_107, 0x1ed,
                              0xb7, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d78);
    {
      TStaticText* namx_108 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d78 /* 'namx' */, namx_108, 0x16f, 0xba, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d78);
    {
      TStaticText* namz_109 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d7a /* 'namz' */, namz_109, 0xbf, 0xd1, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d7a);
    {
      TNumberText* numz_110 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d7a /* 'numz' */, numz_110, 0x13e,
                              0xce, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d7a);
    {
      TStaticText* namx_111 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d78 /* 'namx' */, namx_111, 0x16f, 0xd1, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d78);
    {
      TNumberText* numx_112 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d78 /* 'numx' */, numx_112, 0x1ed,
                              0xce, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d78);
    {
      TStaticText* nam__113 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d7b /* 'nam{' */, nam__113, 0xa, 0xe7, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d7b);
    {
      TNumberText* num__114 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d7b /* 'num{' */, num__114, 0x88,
                              0xe4, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d7b);
    {
      TStaticText* nam__115 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d7c /* 'nam|' */, nam__115, 0xbf, 0xe8, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d7c);
    {
      TNumberText* num__116 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d7c /* 'num|' */, num__116, 0x13e,
                              0xe5, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d7c);
    {
      TStaticText* nam__117 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d7e /* 'nam~' */, nam__117, 0xbf, 0x100, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d7e);
    {
      TNumberText* num__118 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d7e /* 'num~' */, num__118, 0x13e,
                              0xfd, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d7e);
    {
      TStaticText* nam__119 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d7d /* 'nam}' */, nam__119, 9, 0x101, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d7d);
    {
      TNumberText* wind_120 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d7d /* 'num}' */, wind_120, 0x88,
                              0xfe, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d7d /* 'num}' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x24f9: {

    {
      TWindow* wind_62 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_62, 0x3e, 0x25, 0x118,
                              0x103, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* dlog_121 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, dlog_121, 0, 0, 0x118, 0x103, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24f9);
      ClearUiResourceContext();
    }
    {
      TUpDownPictureButton* wind_122 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x20202020 /* '    ' */, wind_122, 0xc6, 0xdd, 0x3d,
                              0x18, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x20202020);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x2502: {

    {
      TWindow* wind_63 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_63, 0xa0, 0x8a, 0x15e,
                              0xfa, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* dlog_123 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, dlog_123, 0, 0, 0x15e, 0xfa, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x605);
      ClearUiResourceContext();
    }
    {
      TStaticText* titl_124 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7469746c /* 'titl' */, titl_124, 0xc, 0xa, 0x146,
                              0x17, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xe, g_szUiTaskForceReport_006947D8, 3, 1, 0x12, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c);
    {
      TStaticText* lab1_125 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_125, 0x14, 0x23, 0x133,
                              0xe, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xf, g_szUiForceCurrentlyLocated_006947B0, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TStaticText* whom_126 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x77686f6d /* 'whom' */, whom_126, 0x10, 0x6b, 0x96,
                              0x57, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x12, g_szUiOneHenTwoDucks_006948AC, 3, 0, 0xc, 0, -2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x77686f6d);
    {
      TStaticText* lab3_127 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616233 /* 'lab3' */, lab3_127, 0xb8, 0x54, 0x92,
                              0x12, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xa, g_szUiOrdersLabel_006948A4, 3, 5, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616233);
    {
      TStaticText* ords_128 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6f726473 /* 'ords' */, ords_128, 0xc5, 0x6c, 0x87,
                              0x32, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x16, g_szUiPatrolTheWaters_0069487C, 3, 0, 0xc, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f726473);
    {
      TStaticText* agro_129 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6167726f /* 'agro' */, agro_129, 0xc6, 0xa7, 0x83,
                              0x1e, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x11, g_szUiEngageAllFloating_0069478C, 3, 2, 0xa, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6167726f);
    {
      TUpDownPictureButton* canc_130 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagCanc, canc_130, 0xbb, 0xd5, 0x3d, 0x17, 1,
                              1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c4);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x63616e63);
    {
      TUpDownPictureButton* okay_131 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okay_131, 0x10c, 0xd5, 0x3d, 0x18,
                              1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);
    {
      TStaticText* lab2_132 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616232 /* 'lab2' */, lab2_132, 0x11, 0x54, 0x92,
                              0x12, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xb, g_szUiCompositionLabel_0069486C, 3, 5, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616232);
    {
      TStaticText* adam_133 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6164616d /* 'adam' */, adam_133, 0xf, 0xc9, 0x97,
                              0x1b, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1e, g_szUiAdmiralBobMinnow_00694840, 3, 0, 0xa, 0, -2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6164616d);
    {
      TStaticText* wind_134 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7a6f6e65 /* 'zone' */, wind_134, 0xb, 0x32, 0x148,
                              0x11, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1f, g_szUiSeaOfSalamanders_0069476C, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7a6f6e65);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x2505: {

    {
      TWindow* wind_64 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_64, 0xa0, 0x8a, 0x15e,
                              0x113, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* dlog_135 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, dlog_135, 0, 0, 0x15e, 0x113, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x605);
      ClearUiResourceContext();
    }
    {
      TStaticText* titl_136 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7469746c /* 'titl' */, titl_136, 0x29, 0xa, 0x10b,
                              0x1a, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x25, g_szUiEnemyTradeInterrupted_00694750, 3, 1, 0x12, 0,
                                 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c);
    {
      TStaticText* miss_137 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6d697373 /* 'miss' */, miss_137, 0xb5, 0x69, 0x9e,
                              0x10, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x26, g_szUiBlockadeLabel_00694744, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6d697373);
    {
      TStaticText* lab1_138 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_138, 0xb4, 0x58, 0x9f,
                              0xc, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x27, g_szUiResultOfSuccessful_00694724, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TUpDownPictureButton* okay_139 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okay_139, 0x113, 0xf0, 0x3d, 0x18,
                              1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);
    {
      TStaticText* vess_140 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x76657373 /* 'vess' */, vess_140, 0xbe, 0xbf, 0x8c,
                              0x2b, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x28, g_szUiThreeVessels_00694718, 3, 1, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x76657373);
    {
      TStaticText* zone_141 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7a6f6e65 /* 'zone' */, zone_141, 0x10, 0x32, 0x142,
                              0x13, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x18, g_szUiSeaOfOblongata_00694704, 3, 1, 0xe, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7a6f6e65);
    {
      TStaticText* lab2_142 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616232 /* 'lab2' */, lab2_142, 0x91, 0x23, 0x35,
                              0xc, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x19, g_szUiInThe_006946FC, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616232);
    {
      TStaticText* adam_143 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6164616d /* 'adam' */, adam_143, 0xb6, 0x8f, 0x98,
                              0x1a, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1b, g_szUiAdmiralKirk_006946C8, 3, 3, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6164616d);
    PopUiResourcePoolNode(0x444c4f47);
    {
      TStaticText* lab1_144 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_144, 0xb7, 0x7d, 0x9a,
                              0x10, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x29, g_szUiByTaskForceCommandedBy_006946A4, 3, 0, 0xa, 0,
                                 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TStaticText* lab1_145 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_145, 0xb1, 0xae, 0xa6,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x2a, g_szUiAndConsistingOf_0069468C, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TStaticText* lab1_146 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_146, 7, 0x59, 0xa6,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x2b, g_szUiMerchantsBelongingTo_00694670, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TStaticText* ownr_147 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6f776e72 /* 'ownr' */, ownr_147, 0x29, 0x68, 0x61,
                              0x10, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x2c, g_szUiOwnrTag_00694668, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f776e72);
    {
      TStaticText* lab1_148 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_148, 7, 0x7a, 0xa6,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x2d, g_szUiCarryingCargoOf_00694650, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TStaticText* gpee_149 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x67706565 /* 'gpee' */, gpee_149, 0x29, 0x8d, 0x61,
                              0x10, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x2e, g_szUiItemLabel_00694648, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x67706565);
    {
      TStaticText* lab1_150 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_150, 7, 0x9e, 0xa6,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x2f, g_szUiToLabel_00694644, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TStaticText* dest_151 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x64657374 /* 'dest' */, dest_151, 0x29, 0xae, 0x61,
                              0x10, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x30, g_szUiPlaceholderPokei_0069463C, 3, 1, 0xc, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x64657374);
    {
      TStaticText* what_152 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x77686174 /* 'what' */, what_152, 9, 0xc0, 0xa1,
                              0x1d, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x31, g_szUiStoppedFromTrade_00694608, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x77686174);
    {
      TStaticText* wind_153 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7369657a /* 'siez' */, wind_153, 0x15, 0xdb, 0x8a,
                              0x24, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x32, g_szUiTraderIndiamen_006945EC, 3, 1, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7369657a /* 'siez' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x24f6: {

    {
      TWindow* wind_65 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_65, 0xe, 0x3b, 0x258,
                              0x12c, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 1, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* w154 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, 0x20202020 /* '    ' */, w154, 0, 0, 0x258, 0x12c, 0,
                              1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24f5);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x20202020);
    {
      TNumberText* numd_155 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d64 /* 'numd' */, numd_155, 0x155,
                              0x22, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d64);
    {
      TStaticText* namd_156 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d64 /* 'namd' */, namd_156, 0xd7, 0x25, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d64);
    {
      TStaticText* name_157 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, kControlTagName, name_157, 0xd7, 0x3c, 0x6e, 0xf, 0,
                              1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 7, g_szUiSkirmishersLabel_006947FC, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d65);
    {
      TNumberText* nume_158 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d65 /* 'nume' */, nume_158, 0x155,
                              0x39, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d65);
    {
      TStaticText* namh_159 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d68 /* 'namh' */, namh_159, 0xd7, 0x53, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 8, g_szUiRegularsLabel_006947F0, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d68);
    {
      TNumberText* numh_160 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d68 /* 'numh' */, numh_160, 0x155,
                              0x50, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d68);
    {
      TNumberText* numi_161 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d69 /* 'numi' */, numi_161, 0x155,
                              0x67, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d69);
    {
      TStaticText* nami_162 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d69 /* 'nami' */, nami_162, 0xd7, 0x6a, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d69);
    {
      TStaticText* namm_163 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6d /* 'namm' */, namm_163, 0xd7, 0xaf, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6d);
    {
      TNumberText* owne_164 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6f776e65 /* 'owne' */, owne_164, 0x193,
                              0xdd, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f776e65);
    {
      TStaticText* naml_165 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6c /* 'naml' */, naml_165, 0xd7, 0x98, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6c);
    {
      TNumberText* numl_166 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6c /* 'numl' */, numl_166, 0x155,
                              0x95, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6c);
    {
      TNumberText* numj_167 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6a /* 'numj' */, numj_167, 0x155,
                              0x7e, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6a);
    {
      TStaticText* namj_168 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6e616d6a /* 'namj' */, namj_168, 0xd7, 0x81, 0x6e,
                              0xf, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiMinutemanLabel_0069480C, 0, 0, 0, 0, -1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e616d6a);
    {
      TUpDownPictureButton* w169 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, 0x20202020 /* '    ' */, w169, 0x11f, 0xf0, 0x3d,
                              0x18, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x20202020);
    {
      TNumberText* dlog_170 = new TNumberText();

      RegisterUiResourceEntry(0x6e6d6272 /* 'nmbr' */, 0x6e756d6d /* 'numm' */, dlog_170, 0x155,
                              0xac, 0x24, 0x16, 1, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 0);
      SetUiResourceLayoutValues(6, 3, 3, 3, 3);
      BindUiResourceTextAndStyle(-1, -1, g_szUiPlaceholderZero_00694378, 0, 0, 0, 0, 0);
      SetUiResourceContextMaxCharCount(0xff);
      SetUiResourceContextNumberValueAndRange(0, 0, 0xff);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6e756d6d /* 'numm' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x2506: {

    {
      TWindow* wind_66 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_66, 0x11, 0x33, 0x1e0,
                              0x190, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }

    {
      TBook* gold_67 = new TBook();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, gold_67, 0, 0, 0x1e0, 0x190, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdac);
      ClearUiResourceContext();
    }
    {
      TPictureButton* wind_171 = new TPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, wind_171, 0x1a, 0xb, 0x1d, 0x1d, 1,
                              0, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb3);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);

    {
      TNavyRoster* page_68 = new TNavyRoster();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x70616765 /* 'page' */, page_68, 0xd, 0x2e,
                              0x1ca, 0x136, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x70616765);

    {
      TColorKeyPicture* lcor_69 = new TColorKeyPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6c636f72 /* 'lcor' */, lcor_69, 0xc, 0x164, 0x29,
                              0x24, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c636f72);

    {
      TColorKeyPicture* rcor_70 = new TColorKeyPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x72636f72 /* 'rcor' */, rcor_70, 0x1b0, 0x164, 0x29,
                              0x24, 1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0xdb1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x72636f72);
    PopUiResourcePoolNode(0x444c4f47 /* 'DLOG' */);
    PopUiResourcePoolNode(0x57494e44 /* 'WIND' */);
  } break;

  case 0x2503: {

    {
      TWindow* wind_71 = new TWindow();
      RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, wind_71, 0xa0, 0x8a, 0x15e,
                              0xfa, 1, 1, 0, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
      ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
      ClearUiResourceContext();
    }
    {
      TPicture* dlog_172 = new TPicture();

      RegisterUiResourceEntry(kControlTagPict, kControlTagGold, dlog_172, 0, 0, 0x15e, 0xfa, 0, 1,
                              kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x606);
      ClearUiResourceContext();
    }
    {
      TStaticText* titl_173 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7469746c /* 'titl' */, titl_173, 5, 0xa, 0x154,
                              0x19, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xc, g_szUiForeignFleetReport_006945D0, 3, 1, 0x12, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7469746c);
    {
      TStaticText* gpee_174 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x67706565 /* 'gpee' */, gpee_174, 5, 0x30, 0x154,
                              0x10, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0xd, g_szUiPlaceholderPont_006945C8, 3, 1, 0xe, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x67706565);
    {
      TStaticText* lab1_175 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616231 /* 'lab1' */, lab1_175, 5, 0x22, 0x154,
                              0xf, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x10, g_szUiNavalForcesReportOf_006945A4, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616231);
    {
      TUpDownPictureButton* okay_176 = new TUpDownPictureButton();

      RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okay_176, 0x113, 0xd8, 0x3d, 0x18,
                              1, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
      SetUiResourceContextPictureId(0x24c2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6f6b6179);
    {
      TStaticText* ship_177 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x73686970 /* 'ship' */, ship_177, 0xf, 0x85, 0x140,
                              0x43, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x17, g_szUiHalfDozenShips_00694574, 3, 0, 0xc, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x73686970);
    {
      TStaticText* zone_178 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x7a6f6e65 /* 'zone' */, zone_178, 5, 0x4f, 0x154,
                              0x13, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x18, g_szUiSeaOfOblongata_00694704, 3, 1, 0xe, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x7a6f6e65);
    {
      TStaticText* lab2_179 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616232 /* 'lab2' */, lab2_179, 5, 0x42, 0x154,
                              0xd, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x19, g_szUiInThe_006946FC, 3, 0, 0xa, 0, 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616232);
    {
      TStaticText* adam_180 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6164616d /* 'adam' */, adam_180, 0x12, 0xe1, 0x109,
                              0xd, 0, 1, kControlTagGold, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1b, g_szUiAdmiralKirk_006946C8, 3, 2, 0xa, 0, 0);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6164616d);
    PopUiResourcePoolNode(0x444c4f47);
    {
      TStaticText* lab3_181 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616233 /* 'lab3' */, lab3_181, 5, 0x70, 0x154,
                              0x12, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1c, g_szUiForeignShippingObserved_00694554, 3, 5, 0xc, 0,
                                 1);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616233);
    {
      TStaticText* lab4_182 = new TStaticText();

      RegisterUiResourceEntry(kControlTagStat, 0x6c616234 /* 'lab4' */, lab4_182, 0x17, 0xd2, 0xf4,
                              0xd, 0, 1, kControlTagWind, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 0x1d, g_szUiAsEstimatedBy_00694540, 3, 2, 0xa, 0, -2);
      ClearUiResourceContext();
    }
    PopUiResourcePoolNode(0x6c616234);
    PopUiResourcePoolNode(0x57494e44);
  } break;

  default:
    return 0;
  }

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
