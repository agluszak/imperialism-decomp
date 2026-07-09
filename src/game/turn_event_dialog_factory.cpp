#include "game/turn_event_dialog_factory.h"

#include "game/TBook.h"
#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TDropShadowNumberText.h"
#include "game/TDropShadowText.h"
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
#include "game/ui_resource_pool.h"

namespace {

static __inline void PushUiWidgetBuildStackNode(TView* node) {
  POSITION (CList<TView*, TView*>::*addTail)(TView*) = &CList<TView*, TView*>::AddTail;
  (g_UiWidgetBuildStack006a13e0.*addTail)(node);
}
static __inline void PopUiWidgetBuildStackNode() {
  TView* (CList<TView*, TView*>::*removeTail)() = &CList<TView*, TView*>::RemoveTail;
  (g_UiWidgetBuildStack006a13e0.*removeTail)();
}

TView* BuildTurnOrderNavigationWindow(int offsetX, int offsetY, int width, int height,
                                      unsigned short layoutModeWord) {
  TGameWindow* window = new TGameWindow();
  if (window == 0) {
    return 0;
  }

  if (g_pUiResourceHead == 0) {
    g_pUiResourceHead = window;
  }
  g_pUiResourceContext = window;

  PushUiWidgetBuildStackNode(window);

  int offsetLayout[2] = {offsetX, offsetY};
  int sizeLayout[2] = {width, height};
  window->InitializeUiResourceEntryFrameAndParent(0, 0, offsetLayout, sizeLayout, 0, 0, 1);

  window->controlTag = static_cast<int>(kControlTagWind);
  window->controlValue3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(width, 0);
  window->inputGateFlag4c = 1;
  window->childHitTestFlag4d = 1;

  if (window->stylePayload48 != 0) {
    delete window->stylePayload48;
    window->stylePayload48 = 0;
  }
  window->EnsureField48Buffer();
  if (window->stylePayload48 != 0) {
    window->stylePayload48->Reset();
    window->stylePayload48->styleWord = 0;
    window->stylePayload48->packedColor = 0xffffff;
  }

  window->useCaptionedFrameFlag6d = 0;
  window->flag6e = 1;
  window->flag6f = 1;
  window->flag71 = 1;
  window->windowStyleType = static_cast<short>(layoutModeWord);
  window->field9c = 8;

  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

// Startup intro screen (event code 0x11f8): a root TView container ('base' tag, a
// large logical 2000x2000 layout area) holding a full-screen 640x480 TPicture ('main'
// tag) that loads bitmap resource 0x11f7. Verified against the retail disassembly at
// 0x0043b1cb (inside BuildTurnEventDialogUiByCode's body — Ghidra reports that whole
// function as 25768 bytes; this is one of its many event-code cases, not a separate
// function).
//
// Hosting mechanism (bd 1uj.10): this tree deliberately propagates a null native
// window here, exactly like the other factories. The real host hookup happens after
// the factory returns: the tree is attached under the TIncludeView packet (which
// inherited the main view's nativeWindow50), and the packet's NoOpUiLifecycleHook tail
// sends message 0x4ef (wParam 1) to that window — CIncludeView::OnDialogTreeHostMsg4EF
// then re-propagates the CIncludeView itself as every node's native window and
// re-resolves 'main'. Painting flows through CIncludeView::OnDraw's slot-0x43
// recursion over the hosted tree.
TView* BuildStartupIntroBackground() {
  TView* parent;

  TView* container = new TView();
  if (container == 0) {
    return 0;
  }

  g_pUiResourceContext = container;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = container;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(container);

  int containerOffset[2] = {0, 0};
  int containerSize[2] = {0x7d0, 0x7d0};
  container->InitializeUiResourceEntryFrameAndParent(0, parent, containerOffset, containerSize, 0,
                                                     0, 1);
  container->controlTag = static_cast<int>(kControlTagBase);
  container->controlValue3c = 0;
  container->SetEnabled(1, 0);
  container->SetState(containerSize[0], 0);

  TPicture* background = new TPicture();
  if (background != 0) {
    g_pUiResourceContext = background;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = background;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(background);

    int pictureOffset[2] = {0, 0};
    int pictureSize[2] = {0x280, 0x1e0};
    background->InitializeUiResourceEntryFrameAndParent(0, parent, pictureOffset, pictureSize, 0, 0,
                                                        1);
    background->controlTag = static_cast<int>(kControlTagMain);
    background->controlValue3c = 0;
    background->SetEnabled(1, 0);
    background->SetState(pictureSize[0], 0);

    background->EnsureField48Buffer();
    if (background->stylePayload48 != 0) {
      background->stylePayload48->styleWord = 0;
      background->stylePayload48->packedColor = 0xffffff;
    }

    background->hasCommandTagResource = 0xa;
    background->field68 = 0;
    background->field6C = 0;
    background->field70 = 0;

    background->SetPictureResourceIdAndRefresh(0x11f7, 0);

    TMovieView* movie = new TMovieView();
    if (movie != 0) {
      g_pUiResourceContext = movie;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = movie;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(movie);

      int movieOffset[2] = {0xc8, 0x64};
      int movieSize[2] = {0x11c, 0xe8};
      movie->InitializeUiResourceEntryFrameAndParent(0, parent, movieOffset, movieSize, 0, 0, 1);
      movie->controlTag = static_cast<int>(kControlTagMovi);
      movie->controlValue3c = 0;
      movie->SetEnabled(1, 0);
      movie->SetState(1, 0);

      movie->EnsureField48Buffer();
      if (movie->stylePayload48 != 0) {
        movie->stylePayload48->styleWord = 0;
        movie->stylePayload48->packedColor = 0xffffff;
      }

      movie->hasCommandTagResource = 0xa;
      movie->field68 = 0;
      movie->field6C = 0;
      movie->field70 = 0;

      movie->SetPictureResourceIdAndRefresh(0x11f7, 0);
      PopUiWidgetBuildStackNode();
    }
    PopUiWidgetBuildStackNode();
  }

  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

// Event 0x3a98 (keystone case at 0x0043b099): a single bare 200x200 'WIND' window at
// (0x9c,0x38) with the gold dialog behavior. Unlike the sibling cases, the original
// case body uses the expanded (non-helper) idiom: field writes re-read
// g_pUiResourceContext per statement group, and the pop is a direct RemoveTail.
TView* BuildBareGoldEventWindow3A98() {
  TView* parent;

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
  offset[0] = 0x9c;
  offset[1] = 0x38;
  size[0] = 0xc8;
  size[1] = 0xc8;
  window->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  window->controlTag = static_cast<int>(kControlTagWind);
  window->controlValue3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(1, 0);

  g_pUiResourceContext->inputGateFlag4c = 1;
  g_pUiResourceContext->childHitTestFlag4d = 1;

  TWindow* context = static_cast<TWindow*>(g_pUiResourceContext);
  context->topmostFlag70 = 0;
  context->flag6f = 1;
  context->flag6e = 1;
  context->useCaptionedFrameFlag6d = 0;
  context->flag6c = 1;
  context->flag71 = 1;
  context->field9c = 8;
  context->windowStyleType = 2;

  TWindow* behaviorOwner = static_cast<TWindow*>(g_pUiResourceContext);
  behaviorOwner->GetEmbeddedDialogBehavior()->SetFlag0C(1);
  behaviorOwner->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020,
                                                                              0x20202020);

  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

} // namespace

// Turn-event dialog factory callbacks registered by InitializeTurnEventDialogFactoryRegistry.
// Each is invoked as factory(0, nEventCode) from RunRegisteredDialogFactoriesByEventCode.

// FUNCTION: IMPERIALISM 0x00415fe0
TView* __cdecl BuildTradeSchoolDialogControls(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0041b6d0
TView* __cdecl InitializeIndustryViewTradeMoveControlsAndCommodityRows(CWnd* pHostWindow,
                                                                       int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00427360
TView* __cdecl InitializeIndustryOverviewPlacardsAndTradeStatusTags(CWnd* pHostWindow,
                                                                    int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004295a0
TView* __cdecl BuildTurnEventDialogResourcesForEvent547Or7D8(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00430c50
TView* __cdecl InitializeDealBookScreenControlsAndCommandTags(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004357b0
TView* __cdecl BuildTurnEventDialogUiByCode(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  g_pUiResourceHead = 0;

  switch (static_cast<unsigned short>(nEventCode)) {
  case 0x7d1:
    return BuildTurnOrderNavigationWindow(5, 0x32, 0x258, 400, 2);
  case 0x7d2:
    return BuildTurnOrderNavigationWindow(0, 0x28, 0x280, 0x1e0, 4);
  case 0x3a98:
    return BuildBareGoldEventWindow3A98();
  case 0x11f8:
    return BuildStartupIntroBackground();
  default:
    return nullptr;
  }
}

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
      reportView->hasCommandTagResource = 0xa;
      CRect zeroRect(0, 0, 0, 0);
      reportView->field68 = zeroRect.left;
      reportView->field6C = zeroRect.top;
      reportView->field70 = zeroRect.right;
      reportView->field74 = zeroRect.bottom;
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
      titleText->hasCommandTagResource = 0xd;
      CRect zeroRect(0, 0, 0, 0);
      titleText->field68 = zeroRect.left;
      titleText->field6C = zeroRect.top;
      titleText->field70 = zeroRect.right;
      titleText->field74 = zeroRect.bottom;
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
      whomText->hasCommandTagResource = 0xd;
      CRect zeroRect(0, 0, 0, 0);
      whomText->field68 = zeroRect.left;
      whomText->field6C = zeroRect.top;
      whomText->field70 = zeroRect.right;
      whomText->field74 = zeroRect.bottom;
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
  static_cast<TWindow*>(g_pUiResourceContext)->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0x22;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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

// FUNCTION: IMPERIALISM 0x0044af90
TView* __cdecl InitializeJoinSelectorDialogControlsAndNationSlots(CWnd* pHostWindow,
                                                                  int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044fbc0
TView* __cdecl BuildUiResourceTreeByTemplateIdAndBindScreenContext(CWnd* pHostWindow,
                                                                   int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

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
      w2->hasCommandTagResource = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w2->field68 = layoutRect.left;
      w2->field6C = layoutRect.top;
      w2->field70 = layoutRect.right;
      w2->field74 = layoutRect.bottom;
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
      w3->hasCommandTagResource = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w3->field68 = layoutRect.left;
      w3->field6C = layoutRect.top;
      w3->field70 = layoutRect.right;
      w3->field74 = layoutRect.bottom;
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
      w4->hasCommandTagResource = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w4->field68 = layoutRect.left;
      w4->field6C = layoutRect.top;
      w4->field70 = layoutRect.right;
      w4->field74 = layoutRect.bottom;
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
      w5->hasCommandTagResource = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w5->field68 = layoutRect.left;
      w5->field6C = layoutRect.top;
      w5->field70 = layoutRect.right;
      w5->field74 = layoutRect.bottom;
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
      w6->hasCommandTagResource = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w6->field68 = layoutRect.left;
      w6->field6C = layoutRect.top;
      w6->field70 = layoutRect.right;
      w6->field74 = layoutRect.bottom;
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
      w7->hasCommandTagResource = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w7->field68 = layoutRect.left;
      w7->field6C = layoutRect.top;
      w7->field70 = layoutRect.right;
      w7->field74 = layoutRect.bottom;
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
      w8->hasCommandTagResource = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w8->field68 = layoutRect.left;
      w8->field6C = layoutRect.top;
      w8->field70 = layoutRect.right;
      w8->field74 = layoutRect.bottom;
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
      w9->hasCommandTagResource = 5;
      CRect layoutRect(0, 0, 0, 0);
      w9->field68 = layoutRect.left;
      w9->field6C = layoutRect.top;
      w9->field70 = layoutRect.right;
      w9->field74 = layoutRect.bottom;
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
      w10->hasCommandTagResource = 0xc;
      CRect layoutRect(0, 0, 0, 0);
      w10->field68 = layoutRect.left;
      w10->field6C = layoutRect.top;
      w10->field70 = layoutRect.right;
      w10->field74 = layoutRect.bottom;
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
      w11->field68 = layoutRect.left;
      w11->field6C = layoutRect.top;
      w11->field70 = layoutRect.right;
      w11->field74 = layoutRect.bottom;
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
      w12->hasCommandTagResource = 0xc;
      CRect layoutRect(0, 0, 0, 0);
      w12->field68 = layoutRect.left;
      w12->field6C = layoutRect.top;
      w12->field70 = layoutRect.right;
      w12->field74 = layoutRect.bottom;
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
      w13->hasCommandTagResource = 0xc;
      CRect layoutRect(0, 0, 0, 0);
      w13->field68 = layoutRect.left;
      w13->field6C = layoutRect.top;
      w13->field70 = layoutRect.right;
      w13->field74 = layoutRect.bottom;
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
      w14->hasCommandTagResource = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w14->field68 = layoutRect.left;
      w14->field6C = layoutRect.top;
      w14->field70 = layoutRect.right;
      w14->field74 = layoutRect.bottom;
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
      w15->hasCommandTagResource = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w15->field68 = layoutRect.left;
      w15->field6C = layoutRect.top;
      w15->field70 = layoutRect.right;
      w15->field74 = layoutRect.bottom;
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
      w16->hasCommandTagResource = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w16->field68 = layoutRect.left;
      w16->field6C = layoutRect.top;
      w16->field70 = layoutRect.right;
      w16->field74 = layoutRect.bottom;
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
      w17->hasCommandTagResource = 0x22;
      CRect layoutRect(0, 0, 0, 0);
      w17->field68 = layoutRect.left;
      w17->field6C = layoutRect.top;
      w17->field70 = layoutRect.right;
      w17->field74 = layoutRect.bottom;
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
      w18->hasCommandTagResource = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w18->field68 = layoutRect.left;
      w18->field6C = layoutRect.top;
      w18->field70 = layoutRect.right;
      w18->field74 = layoutRect.bottom;
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
      w19->hasCommandTagResource = 6;
      CRect layoutRect(3, 3, 3, 3);
      w19->field68 = layoutRect.left;
      w19->field6C = layoutRect.top;
      w19->field70 = layoutRect.right;
      w19->field74 = layoutRect.bottom;
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
      w2->hasCommandTagResource = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w2->field68 = layoutRect.left;
      w2->field6C = layoutRect.top;
      w2->field70 = layoutRect.right;
      w2->field74 = layoutRect.bottom;
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
      w3->hasCommandTagResource = 0xd;
      CRect layoutRect(0, 0, 0, 0);
      w3->field68 = layoutRect.left;
      w3->field6C = layoutRect.top;
      w3->field70 = layoutRect.right;
      w3->field74 = layoutRect.bottom;
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
      w2->hasCommandTagResource = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w2->field68 = layoutRect.left;
      w2->field6C = layoutRect.top;
      w2->field70 = layoutRect.right;
      w2->field74 = layoutRect.bottom;
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
      w4->hasCommandTagResource = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w4->field68 = layoutRect.left;
      w4->field6C = layoutRect.top;
      w4->field70 = layoutRect.right;
      w4->field74 = layoutRect.bottom;
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
      w5->hasCommandTagResource = 0xa;
      CRect layoutRect(0, 0, 0, 0);
      w5->field68 = layoutRect.left;
      w5->field6C = layoutRect.top;
      w5->field70 = layoutRect.right;
      w5->field74 = layoutRect.bottom;
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

// FUNCTION: IMPERIALISM 0x0045b100
TView* __cdecl InitializeTacticalBattleViewToolbarAndDialogControls(CWnd* pHostWindow,
                                                                    int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xd;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 5;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xd;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
    static_cast<TControl*>(g_pUiResourceContext)->hasCommandTagResource = 0xd;
#pragma inline_depth(0)
    CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
    static_cast<TControl*>(g_pUiResourceContext)->field68 = zeroRect.left;
    static_cast<TControl*>(g_pUiResourceContext)->field6C = zeroRect.top;
    static_cast<TControl*>(g_pUiResourceContext)->field70 = zeroRect.right;
    static_cast<TControl*>(g_pUiResourceContext)->field74 = zeroRect.bottom;
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
      mainBook->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      mainBook->field68 = zeroRect.left;
      mainBook->field6C = zeroRect.top;
      mainBook->field70 = zeroRect.right;
      mainBook->field74 = zeroRect.bottom;
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
      toolbar->hasCommandTagResource = 5;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      toolbar->field68 = zeroRect.left;
      toolbar->field6C = zeroRect.top;
      toolbar->field70 = zeroRect.right;
      toolbar->field74 = zeroRect.bottom;
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
      endButton->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      endButton->field68 = zeroRect.left;
      endButton->field6C = zeroRect.top;
      endButton->field70 = zeroRect.right;
      endButton->field74 = zeroRect.bottom;
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
      seasonLabel->hasCommandTagResource = 0xd;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      seasonLabel->field68 = zeroRect.left;
      seasonLabel->field6C = zeroRect.top;
      seasonLabel->field70 = zeroRect.right;
      seasonLabel->field74 = zeroRect.bottom;
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
      treasuryLabel->hasCommandTagResource = 0xd;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      treasuryLabel->field68 = zeroRect.left;
      treasuryLabel->field6C = zeroRect.top;
      treasuryLabel->field70 = zeroRect.right;
      treasuryLabel->field74 = zeroRect.bottom;
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
      potToolbar->hasCommandTagResource = 5;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      potToolbar->field68 = zeroRect.left;
      potToolbar->field6C = zeroRect.top;
      potToolbar->field70 = zeroRect.right;
      potToolbar->field74 = zeroRect.bottom;
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
      transportButton->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      transportButton->field68 = zeroRect.left;
      transportButton->field6C = zeroRect.top;
      transportButton->field70 = zeroRect.right;
      transportButton->field74 = zeroRect.bottom;
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
      cityButton->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      cityButton->field68 = zeroRect.left;
      cityButton->field6C = zeroRect.top;
      cityButton->field70 = zeroRect.right;
      cityButton->field74 = zeroRect.bottom;
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
      tradeButton->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      tradeButton->field68 = zeroRect.left;
      tradeButton->field6C = zeroRect.top;
      tradeButton->field70 = zeroRect.right;
      tradeButton->field74 = zeroRect.bottom;
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
      diplomacyButton->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      diplomacyButton->field68 = zeroRect.left;
      diplomacyButton->field6C = zeroRect.top;
      diplomacyButton->field70 = zeroRect.right;
      diplomacyButton->field74 = zeroRect.bottom;
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
    trb2Toolbar->controlTag = static_cast<int>(0x74627232); // 'trb2' (see MISSING-TAG)
    trb2Toolbar->controlValue3c = 0;
    trb2Toolbar->SetEnabled(1, 0);
    trb2Toolbar->SetState(0, 0);
    trb2Toolbar->inputGateFlag4c = 1;
    trb2Toolbar->childHitTestFlag4d = 1;
    {
      trb2Toolbar->hasCommandTagResource = 5;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      trb2Toolbar->field68 = zeroRect.left;
      trb2Toolbar->field6C = zeroRect.top;
      trb2Toolbar->field70 = zeroRect.right;
      trb2Toolbar->field74 = zeroRect.bottom;
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
    topPicture->controlTag = static_cast<int>(0x746f7020); // 'top ' (see MISSING-TAG)
    topPicture->controlValue3c = 0;
    topPicture->SetEnabled(1, 0);
    topPicture->SetState(0, 0);
    topPicture->inputGateFlag4c = 1;
    topPicture->childHitTestFlag4d = 1;
    {
      topPicture->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      topPicture->field68 = zeroRect.left;
      topPicture->field6C = zeroRect.top;
      topPicture->field70 = zeroRect.right;
      topPicture->field74 = zeroRect.bottom;
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
    titleText->controlTag = static_cast<int>(0x7469746c); // 'titl' (see MISSING-TAG)
    titleText->controlValue3c = 0;
    titleText->SetEnabled(1, 0);
    titleText->SetState(0, 0);
    titleText->inputGateFlag4c = 1;
    titleText->childHitTestFlag4d = 1;
    {
      titleText->hasCommandTagResource = 0xd;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      titleText->field68 = zeroRect.left;
      titleText->field6C = zeroRect.top;
      titleText->field70 = zeroRect.right;
      titleText->field74 = zeroRect.bottom;
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
      patchPicture->hasCommandTagResource = 0xa;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      patchPicture->field68 = zeroRect.left;
      patchPicture->field6C = zeroRect.top;
      patchPicture->field70 = zeroRect.right;
      patchPicture->field74 = zeroRect.bottom;
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
    scrollView->controlTag = static_cast<int>(0x73637677); // 'scvw' (see MISSING-TAG)
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
      okayButton->hasCommandTagResource = 0x22;
#pragma inline_depth(0)
      CRect zeroRect(0, 0, 0, 0);
#pragma inline_depth()
      okayButton->field68 = zeroRect.left;
      okayButton->field6C = zeroRect.top;
      okayButton->field70 = zeroRect.right;
      okayButton->field74 = zeroRect.bottom;
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
      main->hasCommandTagResource = 0xa;
      CRect zeroRect(0, 0, 0, 0);
      main->field68 = zeroRect.left;
      main->field6C = zeroRect.top;
      main->field70 = zeroRect.right;
      main->field74 = zeroRect.bottom;
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
      toolbar->controlTag = static_cast<int>(0x74627232); // 'tbr2' (see MISSING-TAG)
      toolbar->controlValue3c = 0;
      toolbar->SetEnabled(1, 0);
      toolbar->SetState(0, 0);
      toolbar->inputGateFlag4c = 1;
      toolbar->childHitTestFlag4d = 1;
      toolbar->hasCommandTagResource = 5;
      CRect zeroRect(0, 0, 0, 0);
      toolbar->field68 = zeroRect.left;
      toolbar->field6C = zeroRect.top;
      toolbar->field70 = zeroRect.right;
      toolbar->field74 = zeroRect.bottom;
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

// FUNCTION: IMPERIALISM 0x0046fd10
TView* __cdecl BuildTurnEventDialogResourcesForEvent7DE(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

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
    w2->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w2->field68 = layoutRect.left;
    w2->field6C = layoutRect.top;
    w2->field70 = layoutRect.right;
    w2->field74 = layoutRect.bottom;
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
    w3->hasCommandTagResource = 6;
    CRect layoutRect(3, 3, 3, 3);
    w3->field68 = layoutRect.left;
    w3->field6C = layoutRect.top;
    w3->field70 = layoutRect.right;
    w3->field74 = layoutRect.bottom;
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
    w4->hasCommandTagResource = 6;
    CRect layoutRect(3, 3, 3, 3);
    w4->field68 = layoutRect.left;
    w4->field6C = layoutRect.top;
    w4->field70 = layoutRect.right;
    w4->field74 = layoutRect.bottom;
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
    w5->hasCommandTagResource = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w5->field68 = layoutRect.left;
    w5->field6C = layoutRect.top;
    w5->field70 = layoutRect.right;
    w5->field74 = layoutRect.bottom;
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
    w6->hasCommandTagResource = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w6->field68 = layoutRect.left;
    w6->field6C = layoutRect.top;
    w6->field70 = layoutRect.right;
    w6->field74 = layoutRect.bottom;
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
    w7->field68 = layoutRect.left;
    w7->field6C = layoutRect.top;
    w7->field70 = layoutRect.right;
    w7->field74 = layoutRect.bottom;
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
    w8->field68 = layoutRect.left;
    w8->field6C = layoutRect.top;
    w8->field70 = layoutRect.right;
    w8->field74 = layoutRect.bottom;
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
    w9->field68 = layoutRect.left;
    w9->field6C = layoutRect.top;
    w9->field70 = layoutRect.right;
    w9->field74 = layoutRect.bottom;
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
    w10->hasCommandTagResource = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w10->field68 = layoutRect.left;
    w10->field6C = layoutRect.top;
    w10->field70 = layoutRect.right;
    w10->field74 = layoutRect.bottom;
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
    w11->hasCommandTagResource = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w11->field68 = layoutRect.left;
    w11->field6C = layoutRect.top;
    w11->field70 = layoutRect.right;
    w11->field74 = layoutRect.bottom;
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
    w12->hasCommandTagResource = 0xd;
    CRect layoutRect(0, 0, 0, 0);
    w12->field68 = layoutRect.left;
    w12->field6C = layoutRect.top;
    w12->field70 = layoutRect.right;
    w12->field74 = layoutRect.bottom;
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
    w13->hasCommandTagResource = 5;
    CRect layoutRect(0, 0, 0, 0);
    w13->field68 = layoutRect.left;
    w13->field6C = layoutRect.top;
    w13->field70 = layoutRect.right;
    w13->field74 = layoutRect.bottom;
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
    w14->hasCommandTagResource = 5;
    CRect layoutRect(0, 0, 0, 0);
    w14->field68 = layoutRect.left;
    w14->field6C = layoutRect.top;
    w14->field70 = layoutRect.right;
    w14->field74 = layoutRect.bottom;
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
    w15->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w15->field68 = layoutRect.left;
    w15->field6C = layoutRect.top;
    w15->field70 = layoutRect.right;
    w15->field74 = layoutRect.bottom;
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
    w16->hasCommandTagResource = 6;
    CRect layoutRect(3, 3, 3, 3);
    w16->field68 = layoutRect.left;
    w16->field6C = layoutRect.top;
    w16->field70 = layoutRect.right;
    w16->field74 = layoutRect.bottom;
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
    w17->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w17->field68 = layoutRect.left;
    w17->field6C = layoutRect.top;
    w17->field70 = layoutRect.right;
    w17->field74 = layoutRect.bottom;
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
    w18->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w18->field68 = layoutRect.left;
    w18->field6C = layoutRect.top;
    w18->field70 = layoutRect.right;
    w18->field74 = layoutRect.bottom;
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
    w19->hasCommandTagResource = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w19->field68 = layoutRect.left;
    w19->field6C = layoutRect.top;
    w19->field70 = layoutRect.right;
    w19->field74 = layoutRect.bottom;
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
    w20->hasCommandTagResource = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w20->field68 = layoutRect.left;
    w20->field6C = layoutRect.top;
    w20->field70 = layoutRect.right;
    w20->field74 = layoutRect.bottom;
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
    w21->hasCommandTagResource = 5;
    CRect layoutRect(0, 0, 0, 0);
    w21->field68 = layoutRect.left;
    w21->field6C = layoutRect.top;
    w21->field70 = layoutRect.right;
    w21->field74 = layoutRect.bottom;
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
    w22->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w22->field68 = layoutRect.left;
    w22->field6C = layoutRect.top;
    w22->field70 = layoutRect.right;
    w22->field74 = layoutRect.bottom;
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
    w23->hasCommandTagResource = 6;
    CRect layoutRect(3, 3, 3, 3);
    w23->field68 = layoutRect.left;
    w23->field6C = layoutRect.top;
    w23->field70 = layoutRect.right;
    w23->field74 = layoutRect.bottom;
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
    w24->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w24->field68 = layoutRect.left;
    w24->field6C = layoutRect.top;
    w24->field70 = layoutRect.right;
    w24->field74 = layoutRect.bottom;
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
    w25->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w25->field68 = layoutRect.left;
    w25->field6C = layoutRect.top;
    w25->field70 = layoutRect.right;
    w25->field74 = layoutRect.bottom;
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
    w26->hasCommandTagResource = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w26->field68 = layoutRect.left;
    w26->field6C = layoutRect.top;
    w26->field70 = layoutRect.right;
    w26->field74 = layoutRect.bottom;
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
    w27->hasCommandTagResource = 5;
    CRect layoutRect(0, 0, 0, 0);
    w27->field68 = layoutRect.left;
    w27->field6C = layoutRect.top;
    w27->field70 = layoutRect.right;
    w27->field74 = layoutRect.bottom;
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
    w28->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w28->field68 = layoutRect.left;
    w28->field6C = layoutRect.top;
    w28->field70 = layoutRect.right;
    w28->field74 = layoutRect.bottom;
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
    w29->hasCommandTagResource = 6;
    CRect layoutRect(3, 3, 3, 3);
    w29->field68 = layoutRect.left;
    w29->field6C = layoutRect.top;
    w29->field70 = layoutRect.right;
    w29->field74 = layoutRect.bottom;
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
    w30->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w30->field68 = layoutRect.left;
    w30->field6C = layoutRect.top;
    w30->field70 = layoutRect.right;
    w30->field74 = layoutRect.bottom;
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
    w31->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w31->field68 = layoutRect.left;
    w31->field6C = layoutRect.top;
    w31->field70 = layoutRect.right;
    w31->field74 = layoutRect.bottom;
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
    w32->hasCommandTagResource = 0xc;
    CRect layoutRect(0, 0, 0, 0);
    w32->field68 = layoutRect.left;
    w32->field6C = layoutRect.top;
    w32->field70 = layoutRect.right;
    w32->field74 = layoutRect.bottom;
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
    w33->hasCommandTagResource = 5;
    CRect layoutRect(0, 0, 0, 0);
    w33->field68 = layoutRect.left;
    w33->field6C = layoutRect.top;
    w33->field70 = layoutRect.right;
    w33->field74 = layoutRect.bottom;
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
    w34->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w34->field68 = layoutRect.left;
    w34->field6C = layoutRect.top;
    w34->field70 = layoutRect.right;
    w34->field74 = layoutRect.bottom;
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
    w35->hasCommandTagResource = 6;
    CRect layoutRect(3, 3, 3, 3);
    w35->field68 = layoutRect.left;
    w35->field6C = layoutRect.top;
    w35->field70 = layoutRect.right;
    w35->field74 = layoutRect.bottom;
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
    w36->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w36->field68 = layoutRect.left;
    w36->field6C = layoutRect.top;
    w36->field70 = layoutRect.right;
    w36->field74 = layoutRect.bottom;
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
    w37->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w37->field68 = layoutRect.left;
    w37->field6C = layoutRect.top;
    w37->field70 = layoutRect.right;
    w37->field74 = layoutRect.bottom;
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
    w38->hasCommandTagResource = 5;
    CRect layoutRect(0, 0, 0, 0);
    w38->field68 = layoutRect.left;
    w38->field6C = layoutRect.top;
    w38->field70 = layoutRect.right;
    w38->field74 = layoutRect.bottom;
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
    w39->hasCommandTagResource = 0xa;
    CRect layoutRect(0, 0, 0, 0);
    w39->field68 = layoutRect.left;
    w39->field6C = layoutRect.top;
    w39->field70 = layoutRect.right;
    w39->field74 = layoutRect.bottom;
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
