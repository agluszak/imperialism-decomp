#include "game/turn_event_dialog_factory.h"

#include "game/TBook.h"
#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TDropShadowNumberText.h"
#include "game/TDropShadowText.h"
#include "game/TGameSetupPicture.h"
#include "game/TMyNumberText.h"
#include "game/TNoHilitePicture.h"
#include "game/TPageView.h"
#include "game/TScrollView.h"
#include "game/TSidewaysArrow.h"
#include "game/TSliderPicture.h"
#include "game/TTechHistoryView.h"
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
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_resource_pool.h"

namespace {

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

  g_UiWidgetBuildStack006a13e0.AddTail(window);

  int offsetLayout[2] = {offsetX, offsetY};
  int sizeLayout[2] = {width, height};
  window->InitializeUiResourceEntryFrameAndParent(0, 0, offsetLayout, sizeLayout, 0, 0, 1);

  window->controlTag = static_cast<int>(kControlTagWind);
  window->field3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(width, 0);
  window->flag4c = 1;
  window->flag4d = 1;

  if (window->field48 != 0) {
    delete window->field48;
    window->field48 = 0;
  }
  window->EnsureField48Buffer();
  if (window->field48 != 0) {
    window->field48->Reset();
    window->field48->styleWord = 0;
    window->field48->packedColor = 0xffffff;
  }

  window->field6d = 0;
  window->flag6e = 1;
  window->flag6f = 1;
  window->flag71 = 1;
  window->windowStyleType = static_cast<short>(layoutModeWord);
  window->field9c = 8;

  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

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
  g_UiWidgetBuildStack006a13e0.AddTail(container);

  int containerOffset[2] = {0, 0};
  int containerSize[2] = {0x7d0, 0x7d0};
  container->InitializeUiResourceEntryFrameAndParent(0, parent, containerOffset, containerSize, 0,
                                                     0, 1);
  container->controlTag = static_cast<int>(kControlTagBase);
  container->field3c = 0;
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
    g_UiWidgetBuildStack006a13e0.AddTail(background);

    int pictureOffset[2] = {0, 0};
    int pictureSize[2] = {0x280, 0x1e0};
    background->InitializeUiResourceEntryFrameAndParent(0, parent, pictureOffset, pictureSize, 0, 0,
                                                        1);
    background->controlTag = static_cast<int>(kControlTagMain);
    background->field3c = 0;
    background->SetEnabled(1, 0);
    background->SetState(pictureSize[0], 0);

    background->EnsureField48Buffer();
    if (background->field48 != 0) {
      background->field48->styleWord = 0;
      background->field48->packedColor = 0xffffff;
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
      g_UiWidgetBuildStack006a13e0.AddTail(movie);

      int movieOffset[2] = {0xc8, 0x64};
      int movieSize[2] = {0x11c, 0xe8};
      movie->InitializeUiResourceEntryFrameAndParent(0, parent, movieOffset, movieSize, 0, 0, 1);
      movie->controlTag = static_cast<int>(kControlTagMovi);
      movie->field3c = 0;
      movie->SetEnabled(1, 0);
      movie->SetState(1, 0);

      movie->EnsureField48Buffer();
      if (movie->field48 != 0) {
        movie->field48->styleWord = 0;
        movie->field48->packedColor = 0xffffff;
      }

      movie->hasCommandTagResource = 0xa;
      movie->field68 = 0;
      movie->field6C = 0;
      movie->field70 = 0;

      movie->SetPictureResourceIdAndRefresh(0x11f7, 0);
      g_UiWidgetBuildStack006a13e0.RemoveTail();
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
  }

  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

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
  g_UiWidgetBuildStack006a13e0.AddTail(window);

  int offset[2];
  int size[2];
  offset[0] = 0x9c;
  offset[1] = 0x38;
  size[0] = 0xc8;
  size[1] = 0xc8;
  window->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  window->controlTag = static_cast<int>(kControlTagWind);
  window->field3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(1, 0);

  g_pUiResourceContext->flag4c = 1;
  g_pUiResourceContext->flag4d = 1;

  TWindow* context = static_cast<TWindow*>(g_pUiResourceContext);
  context->field70 = 0;
  context->flag6f = 1;
  context->flag6e = 1;
  context->field6d = 0;
  context->flag6c = 1;
  context->flag71 = 1;
  context->field9c = 8;
  context->windowStyleType = 2;

  TWindow* behaviorOwner = static_cast<TWindow*>(g_pUiResourceContext);
  behaviorOwner->GetEmbeddedDialogBehavior()->SetFlag0C(1);
  behaviorOwner->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020,
                                                                              0x20202020);

  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

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
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}

// Diplomatic-message screen for event code 0x2508: a 'WIND' host window at (100,80)
// size 390x282, a full-panel 'GOLD' background picture (bitmap 0x252a) that parents the
// remaining controls, an 'okay' confirm button (bitmap 0x24c2), a 'rewa' reward picture
// (bitmap 0x2508 — same id as the event code), a 'coat' coat-of-arms picture (bitmap
// 0x251c), and an 'info' TDeluxeText block.
// FUNCTION: IMPERIALISM 0x0044a810
TView* __cdecl BuildTurnEventDialogResources_2508(CWnd* pHostWindow, int nEventCode) {
  TView* parent;
  int offset[2];
  int size[2];

  g_pUiResourceHead = 0;
  if (static_cast<short>(nEventCode) != 0x2508) {
    return 0;
  }

  TWindow* window = new TWindow();
  g_pUiResourceContext = window;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = window;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(window);
  offset[0] = 0x64;
  offset[1] = 0x50;
  size[0] = 0x186;
  size[1] = 0x11a;
  window->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  window->controlTag = static_cast<int>(kControlTagWind);
  window->field3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(1, 0);
  window->flag4c = 1;
  window->flag4d = 1;
  window->field70 = 0;
  window->flag6f = 1;
  window->flag6e = 1;
  window->field6d = 0;
  window->flag6c = 0;
  window->flag71 = 1;
  window->field9c = 8;
  window->windowStyleType = 2;
  TDialogBehavior* behavior = window->GetEmbeddedDialogBehavior();
  behavior->SetFlag0C(1);
  window->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);
  g_pUiResourceContext = 0;

  TPicture* goldPanel = new TPicture();
  g_pUiResourceContext = goldPanel;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = goldPanel;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(goldPanel);
  offset[0] = 0;
  offset[1] = 0;
  size[0] = 0x186;
  size[1] = 0x11a;
  goldPanel->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  goldPanel->controlTag = static_cast<int>(kControlTagGold);
  goldPanel->field3c = 0;
  goldPanel->SetEnabled(1, 0);
  goldPanel->SetState(0, 0);
  goldPanel->flag4c = 1;
  goldPanel->flag4d = 1;
  goldPanel->hasCommandTagResource = 0xa;
  goldPanel->field68 = 0;
  goldPanel->field6C = 0;
  goldPanel->field70 = 0;
  goldPanel->field74 = 0;
  goldPanel->SetPictureResourceIdAndRefresh(0x252a, 0);
  g_pUiResourceContext = 0;

  TUpDownPictureButton* okayButton = new TUpDownPictureButton();
  g_pUiResourceContext = okayButton;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = okayButton;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(okayButton);
  offset[0] = 0x136;
  offset[1] = 0xf8;
  size[0] = 0x3d;
  size[1] = 0x17;
  okayButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  okayButton->controlTag = static_cast<int>(kControlTagOkay);
  okayButton->field3c = 0;
  okayButton->SetEnabled(1, 0);
  okayButton->SetState(1, 0);
  okayButton->flag4c = 1;
  okayButton->flag4d = 1;
  okayButton->hasCommandTagResource = 0x22;
  okayButton->field68 = 0;
  okayButton->field6C = 0;
  okayButton->field70 = 0;
  okayButton->field74 = 0;
  okayButton->SetPictureResourceIdAndRefresh(0x24c2, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TPicture* rewardPicture = new TPicture();
  g_pUiResourceContext = rewardPicture;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = rewardPicture;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(rewardPicture);
  offset[0] = 0x70;
  offset[1] = 0x12;
  size[0] = 0xa7;
  size[1] = 0x6d;
  rewardPicture->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  rewardPicture->controlTag = static_cast<int>(kControlTagRewa);
  rewardPicture->field3c = 0;
  rewardPicture->SetEnabled(1, 0);
  rewardPicture->SetState(0, 0);
  rewardPicture->flag4c = 1;
  rewardPicture->flag4d = 1;
  rewardPicture->hasCommandTagResource = 0xa;
  rewardPicture->field68 = 0;
  rewardPicture->field6C = 0;
  rewardPicture->field70 = 0;
  rewardPicture->field74 = 0;
  rewardPicture->SetPictureResourceIdAndRefresh(0x2508, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TPicture* coatPicture = new TPicture();
  RegisterUiResourceEntry(kControlTagPict, kControlTagCoat, coatPicture, 0x127, 0xc, 0x54, 0x7d, 0,
                          1, kControlTagGold, 0);
  coatPicture->flag4c = 1;
  coatPicture->flag4d = 1;
  SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
  coatPicture->SetPictureResourceIdAndRefresh(0x251c, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TDeluxeText* infoText = new TDeluxeText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagInfo, infoText, 0x11, 0xa0, 0x162, 0x54, 0, 1,
                          kControlTagGold, 0);
  infoText->flag4c = 1;
  infoText->flag4d = 0;
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();

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
// FUNCTION: IMPERIALISM 0x004538a0
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(CWnd* pHostWindow, int nEventCode) {
  g_pUiResourceHead = 0;

  if (static_cast<short>(nEventCode) != 0x5dc) {
    return nullptr;
  }

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
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TControl* randButton = new TControl();
  RegisterUiResourceEntry(kControlTagCntl, kControlTagRand, randButton, 0xe, 0xd1, 0x8a, 0xab, 1, 0,
                          kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TControl* multButton = new TControl();
  RegisterUiResourceEntry(kControlTagCntl, kControlTagMult, multButton, 0x1ca, 0x102, 0x8f, 0x8c, 1,
                          0, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TControl* highButton = new TControl();
  RegisterUiResourceEntry(kControlTagCntl, kControlTagHigh, highButton, 0x1c0, 0x71, 0xa4, 0x4e, 1,
                          0, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TControl* scenButton = new TControl();
  RegisterUiResourceEntry(kControlTagCntl, kControlTagScen, scenButton, 1, 0x18d, 0x9c, 0x48, 1, 0,
                          kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TInfoBarText* cursorInfoText = new TInfoBarText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorInfoText, 0xb4, 0x1a8, 0x112,
                          0x34, 0, 1, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TControl* quitButton = new TControl();
  RegisterUiResourceEntry(kControlTagCntl, kControlTagQuit, quitButton, 0xdd, 0x66, 0xc3, 0xc3, 1,
                          0, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TControl* prefButton = new TControl();
  RegisterUiResourceEntry(kControlTagCntl, kControlTagPref, prefButton, 0x21c, 0x18f, 0x64, 0x49, 1,
                          0, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();

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

  g_pUiResourceHead = 0;
  if (static_cast<short>(nEventCode) != 0x898) {
    return 0;
  }

  TView* baseContainer = new TView();
  g_pUiResourceContext = baseContainer;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = baseContainer;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(baseContainer);
  int baseOffset[2] = {0, 0};
  int baseSize[2] = {0x7d0, 0x7d0};
  baseContainer->InitializeUiResourceEntryFrameAndParent(0, parent, baseOffset, baseSize, 0, 0, 1);
  baseContainer->controlTag = static_cast<int>(kControlTagBase);
  baseContainer->field3c = 0;
  baseContainer->SetEnabled(1, 0);
  baseContainer->SetState(0, 0);
  baseContainer->flag4c = 1;
  baseContainer->flag4d = 1;

  TPicture* mainPicture = new TPicture();
  g_pUiResourceContext = mainPicture;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = mainPicture;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(mainPicture);
  int mainOffset[2] = {0, 0};
  int mainSize[2] = {0x280, 0x1e0};
  mainPicture->InitializeUiResourceEntryFrameAndParent(0, parent, mainOffset, mainSize, 0, 0, 1);
  mainPicture->controlTag = static_cast<int>(kControlTagMain);
  mainPicture->field3c = 0;
  mainPicture->SetEnabled(1, 0);
  mainPicture->SetState(0, 0);
  mainPicture->flag4c = 1;
  mainPicture->flag4d = 1;
  // The original re-allocates the 8-byte field48 style payload here (free + alloc +
  // the zeroing helper) before overwriting both slots.
  delete[] mainPicture->field48;
  mainPicture->field48 = 0;
  mainPicture->EnsureField48Buffer();
  if (mainPicture->field48 != 0) {
    mainPicture->field48->styleWord = 0;
    mainPicture->field48->packedColor = 0xffffff;
  }
  mainPicture->hasCommandTagResource = 0xa;
  mainPicture->field68 = 0;
  mainPicture->field6C = 0;
  mainPicture->field70 = 0;
  mainPicture->field74 = 0;
  mainPicture->SetPictureResourceIdAndRefresh(0x898, 0);

  TStaticText* bodyText = new TStaticText();
  g_pUiResourceContext = bodyText;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = bodyText;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(bodyText);
  int bodyOffset[2] = {0x131, 0x14f};
  int bodySize[2] = {0x128, 0x7a};
  bodyText->InitializeUiResourceEntryFrameAndParent(0, parent, bodyOffset, bodySize, 0, 0, 1);
  bodyText->controlTag = static_cast<int>(kControlTagText);
  bodyText->field3c = 0;
  bodyText->SetEnabled(1, 0);
  bodyText->SetState(0, 0);
  bodyText->flag4c = 1;
  bodyText->flag4d = 1;
  bodyText->hasCommandTagResource = 0xd;
  bodyText->field68 = 0;
  bodyText->field6C = 0;
  bodyText->field70 = 0;
  bodyText->field74 = 0;
  BindUiResourceTextAndStyle(0xc80, 1, g_szUiPlaceholderSampleText_00694A98, 3, 0, 0xc, 0, 1);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TToolBarCluster* toolbar = new TToolBarCluster();
  g_pUiResourceContext = toolbar;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = toolbar;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(toolbar);
  int toolbarOffset[2] = {3, 6};
  int toolbarSize[2] = {0xed, 0x5a};
  toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, toolbarOffset, toolbarSize, 0, 0, 1);
  toolbar->controlTag = static_cast<int>(kControlTagTool);
  toolbar->field3c = 0;
  toolbar->SetEnabled(1, 0);
  toolbar->SetState(0, 0);
  toolbar->flag4c = 1;
  toolbar->flag4d = 1;
  toolbar->hasCommandTagResource = 5;
  toolbar->field68 = 0;
  toolbar->field6C = 0;
  toolbar->field70 = 0;
  toolbar->field74 = 0;
  toolbar->field84 = 0x20202020;

  TPictureButton* endButton = new TPictureButton();
  g_pUiResourceContext = endButton;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = endButton;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(endButton);
  int endOffset[2] = {5, 0x20};
  int endSize[2] = {0x1f, 0x33};
  endButton->InitializeUiResourceEntryFrameAndParent(0, parent, endOffset, endSize, 0, 0, 1);
  endButton->controlTag = static_cast<int>(kControlTagEnd);
  endButton->field3c = 0;
  endButton->SetEnabled(0, 0);
  endButton->SetState(1, 0);
  endButton->flag4c = 1;
  endButton->flag4d = 1;
  endButton->hasCommandTagResource = 0xa;
  endButton->field68 = 0;
  endButton->field6C = 0;
  endButton->field70 = 0;
  endButton->field74 = 0;
  endButton->SetPictureResourceIdAndRefresh(0x8b4, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TDropShadowText* seasonLabel = new TDropShadowText();
  g_pUiResourceContext = seasonLabel;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = seasonLabel;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(seasonLabel);
  int seasonOffset[2] = {0x2c, 1};
  int seasonSize[2] = {0x5e, 0x11};
  seasonLabel->InitializeUiResourceEntryFrameAndParent(0, parent, seasonOffset, seasonSize, 0, 0,
                                                       1);
  seasonLabel->controlTag = static_cast<int>(kControlTagSeas);
  seasonLabel->field3c = 0;
  seasonLabel->SetEnabled(1, 0);
  seasonLabel->SetState(0, 0);
  seasonLabel->flag4c = 1;
  seasonLabel->flag4d = 1;
  seasonLabel->hasCommandTagResource = 0xd;
  seasonLabel->field68 = 0;
  seasonLabel->field6C = 0;
  seasonLabel->field70 = 0;
  seasonLabel->field74 = 0;
  BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TDropShadowText* treasuryLabel = new TDropShadowText();
  g_pUiResourceContext = treasuryLabel;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = treasuryLabel;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(treasuryLabel);
  int treasuryOffset[2] = {0x8d, 1};
  int treasurySize[2] = {0x4b, 0x11};
  treasuryLabel->InitializeUiResourceEntryFrameAndParent(0, parent, treasuryOffset, treasurySize, 0,
                                                         0, 1);
  treasuryLabel->controlTag = static_cast<int>(kControlTagTrea);
  treasuryLabel->field3c = 0;
  treasuryLabel->SetEnabled(1, 0);
  treasuryLabel->SetState(0, 0);
  treasuryLabel->flag4c = 1;
  treasuryLabel->flag4d = 1;
  treasuryLabel->hasCommandTagResource = 0xd;
  treasuryLabel->field68 = 0;
  treasuryLabel->field6C = 0;
  treasuryLabel->field70 = 0;
  treasuryLabel->field74 = 0;
  BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TInfoBarText* cursorInfoText = new TInfoBarText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorInfoText, 0xf7, 7, 0x155, 0x11, 0,
                          1, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  TPicture* patchPicture = new TPicture();
  RegisterUiResourceEntry(kControlTagPict, kControlTagPatc, patchPicture, 0x248, 0x23, 0x34, 0x48,
                          0, 1, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
  patchPicture->SetPictureResourceIdAndRefresh(0x8b6, 0);
  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();

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
  if (static_cast<short>(nEventCode) == 0x8fc) {
    TView* baseContainer = new TView();
    g_pUiResourceContext = baseContainer;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = baseContainer;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(baseContainer);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x7d0;
    size[1] = 0x7d0;
    baseContainer->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    baseContainer->controlTag = static_cast<int>(kControlTagBase);
    baseContainer->field3c = 0;
    baseContainer->SetEnabled(1, 0);
    baseContainer->SetState(0, 0);
    baseContainer->flag4c = 1;
    baseContainer->flag4d = 1;
    g_pUiResourceContext = 0;

    TBook* mainBook = new TBook();
    g_pUiResourceContext = mainBook;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = mainBook;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(mainBook);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x280;
    size[1] = 0x1e0;
    mainBook->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    mainBook->controlTag = static_cast<int>(kControlTagMain);
    mainBook->field3c = 0;
    mainBook->SetEnabled(1, 0);
    mainBook->SetState(0, 0);
    mainBook->flag4c = 1;
    mainBook->flag4d = 1;
    delete[] mainBook->field48;
    mainBook->field48 = 0;
    mainBook->EnsureField48Buffer();
    if (mainBook->field48 != 0) {
      mainBook->field48->styleWord = 0;
      mainBook->field48->packedColor = 0xffffff;
    }
    mainBook->hasCommandTagResource = 0xa;
    mainBook->field68 = 0;
    mainBook->field6C = 0;
    mainBook->field70 = 0;
    mainBook->field74 = 0;
    mainBook->SetPictureResourceIdAndRefresh(0x8fc, 0);
    g_pUiResourceContext = 0;

    TToolBarCluster* toolbar = new TToolBarCluster();
    g_pUiResourceContext = toolbar;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = toolbar;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(toolbar);
    offset[0] = 7;
    offset[1] = 6;
    size[0] = 0xe1;
    size[1] = 0x54;
    toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    toolbar->controlTag = static_cast<int>(kControlTagTool);
    toolbar->field3c = 0;
    toolbar->SetEnabled(1, 0);
    toolbar->SetState(0, 0);
    toolbar->flag4c = 1;
    toolbar->flag4d = 1;
    toolbar->hasCommandTagResource = 5;
    toolbar->field68 = 0;
    toolbar->field6C = 0;
    toolbar->field70 = 0;
    toolbar->field74 = 0;
    toolbar->field84 = 0x20202020;
    g_pUiResourceContext = 0;

    TPictureButton* endButton = new TPictureButton();
    g_pUiResourceContext = endButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = endButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(endButton);
    offset[0] = 1;
    offset[1] = 0x20;
    size[0] = 0x1e;
    size[1] = 0x32;
    endButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    endButton->controlTag = static_cast<int>(kControlTagEnd);
    endButton->field3c = 0;
    endButton->SetEnabled(0, 0);
    endButton->SetState(1, 0);
    endButton->flag4c = 1;
    endButton->flag4d = 1;
    endButton->hasCommandTagResource = 0xa;
    endButton->field68 = 0;
    endButton->field6C = 0;
    endButton->field70 = 0;
    endButton->field74 = 0;
    endButton->SetPictureResourceIdAndRefresh(0x8fd, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TDropShadowText* seasonLabel = new TDropShadowText();
    g_pUiResourceContext = seasonLabel;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = seasonLabel;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(seasonLabel);
    offset[0] = 0x2c;
    offset[1] = 4;
    size[0] = 0x5e;
    size[1] = 0x11;
    seasonLabel->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    seasonLabel->controlTag = static_cast<int>(kControlTagSeas);
    seasonLabel->field3c = 0;
    seasonLabel->SetEnabled(1, 0);
    seasonLabel->SetState(0, 0);
    seasonLabel->flag4c = 1;
    seasonLabel->flag4d = 1;
    seasonLabel->hasCommandTagResource = 0xd;
    seasonLabel->field68 = 0;
    seasonLabel->field6C = 0;
    seasonLabel->field70 = 0;
    seasonLabel->field74 = 0;
    BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TDropShadowText* treasuryLabel = new TDropShadowText();
    g_pUiResourceContext = treasuryLabel;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = treasuryLabel;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(treasuryLabel);
    offset[0] = 0x8d;
    offset[1] = 4;
    size[0] = 0x4b;
    size[1] = 0x11;
    treasuryLabel->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    treasuryLabel->controlTag = static_cast<int>(kControlTagTrea);
    treasuryLabel->field3c = 0;
    treasuryLabel->SetEnabled(1, 0);
    treasuryLabel->SetState(0, 0);
    treasuryLabel->flag4c = 1;
    treasuryLabel->flag4d = 1;
    treasuryLabel->hasCommandTagResource = 0xd;
    treasuryLabel->field68 = 0;
    treasuryLabel->field6C = 0;
    treasuryLabel->field70 = 0;
    treasuryLabel->field74 = 0;
    BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TToolBarCluster* potToolbar = new TToolBarCluster();
    g_pUiResourceContext = potToolbar;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = potToolbar;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(potToolbar);
    offset[0] = 0x10b;
    offset[1] = 5;
    size[0] = 0x69;
    size[1] = 0x1a;
    potToolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    potToolbar->controlTag = static_cast<int>(kControlTagBpot);
    potToolbar->field3c = 0;
    potToolbar->SetEnabled(1, 0);
    potToolbar->SetState(0, 0);
    potToolbar->flag4c = 1;
    potToolbar->flag4d = 1;
    potToolbar->hasCommandTagResource = 5;
    potToolbar->field68 = 0;
    potToolbar->field6C = 0;
    potToolbar->field70 = 0;
    potToolbar->field74 = 0;
    potToolbar->field84 = 0x20202020;
    g_pUiResourceContext = 0;

    TUpDownPictureButton* transportButton = new TUpDownPictureButton();
    g_pUiResourceContext = transportButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = transportButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(transportButton);
    offset[0] = 3;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    transportButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    transportButton->controlTag = static_cast<int>(kControlTagTran);
    transportButton->field3c = 0;
    transportButton->SetEnabled(1, 0);
    transportButton->SetState(1, 0);
    transportButton->flag4c = 1;
    transportButton->flag4d = 1;
    transportButton->hasCommandTagResource = 0xa;
    transportButton->field68 = 0;
    transportButton->field6C = 0;
    transportButton->field70 = 0;
    transportButton->field74 = 0;
    transportButton->SetPictureResourceIdAndRefresh(0x24ef, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TUpDownPictureButton* cityButton = new TUpDownPictureButton();
    g_pUiResourceContext = cityButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = cityButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(cityButton);
    offset[0] = 0x1f;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    cityButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    cityButton->controlTag = static_cast<int>(kControlTagCity);
    cityButton->field3c = 0;
    cityButton->SetEnabled(1, 0);
    cityButton->SetState(1, 0);
    cityButton->flag4c = 1;
    cityButton->flag4d = 1;
    cityButton->hasCommandTagResource = 0xa;
    cityButton->field68 = 0;
    cityButton->field6C = 0;
    cityButton->field70 = 0;
    cityButton->field74 = 0;
    cityButton->SetPictureResourceIdAndRefresh(0x24ed, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TUpDownPictureButton* tradeButton = new TUpDownPictureButton();
    g_pUiResourceContext = tradeButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = tradeButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(tradeButton);
    offset[0] = 0x3b;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    tradeButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    tradeButton->controlTag = static_cast<int>(kControlTagTrad);
    tradeButton->field3c = 0;
    tradeButton->SetEnabled(1, 0);
    tradeButton->SetState(1, 0);
    tradeButton->flag4c = 1;
    tradeButton->flag4d = 1;
    tradeButton->hasCommandTagResource = 0xa;
    tradeButton->field68 = 0;
    tradeButton->field6C = 0;
    tradeButton->field70 = 0;
    tradeButton->field74 = 0;
    tradeButton->SetPictureResourceIdAndRefresh(0x24eb, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TUpDownPictureButton* diplomacyButton = new TUpDownPictureButton();
    g_pUiResourceContext = diplomacyButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = diplomacyButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(diplomacyButton);
    offset[0] = 0x58;
    offset[1] = 3;
    size[0] = 0xe;
    size[1] = 0x12;
    diplomacyButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    diplomacyButton->controlTag = static_cast<int>(kControlTagDipl);
    diplomacyButton->field3c = 0;
    diplomacyButton->SetEnabled(1, 0);
    diplomacyButton->SetState(1, 0);
    diplomacyButton->flag4c = 1;
    diplomacyButton->flag4d = 1;
    diplomacyButton->hasCommandTagResource = 0xa;
    diplomacyButton->field68 = 0;
    diplomacyButton->field6C = 0;
    diplomacyButton->field70 = 0;
    diplomacyButton->field74 = 0;
    diplomacyButton->SetPictureResourceIdAndRefresh(0x24e9, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TToolBarCluster* trb2Toolbar = new TToolBarCluster();
    g_pUiResourceContext = trb2Toolbar;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = trb2Toolbar;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(trb2Toolbar);
    offset[0] = 0x258;
    offset[1] = 0x1f;
    size[0] = 0x1e;
    size[1] = 0x30;
    trb2Toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    trb2Toolbar->controlTag = static_cast<int>(0x74627232); // 'trb2' (see MISSING-TAG)
    trb2Toolbar->field3c = 0;
    trb2Toolbar->SetEnabled(1, 0);
    trb2Toolbar->SetState(0, 0);
    trb2Toolbar->flag4c = 1;
    trb2Toolbar->flag4d = 1;
    trb2Toolbar->hasCommandTagResource = 5;
    trb2Toolbar->field68 = 0;
    trb2Toolbar->field6C = 0;
    trb2Toolbar->field70 = 0;
    trb2Toolbar->field74 = 0;
    trb2Toolbar->field84 = 0x20202020;
    g_pUiResourceContext = 0;

    TPictureButton* queryButton = new TPictureButton();
    g_pUiResourceContext = queryButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = queryButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(queryButton);
    offset[0] = 8;
    offset[1] = 9;
    size[0] = 0x16;
    size[1] = 0x26;
    queryButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    queryButton->controlTag = static_cast<int>(kControlTagQuer);
    queryButton->field3c = 0;
    queryButton->SetEnabled(0, 0);
    queryButton->SetState(1, 0);
    queryButton->flag4c = 1;
    queryButton->flag4d = 1;
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    queryButton->SetPictureResourceIdAndRefresh(0x8fe, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TPageView* pageView = new TPageView();
    RegisterUiResourceEntry(0x76696577, 0x70616765, pageView, 0x26, 0x40, 0x232, 0x17a, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TNoHilitePicture* leftCorner = new TNoHilitePicture();
    RegisterUiResourceEntry(kControlTagPict, 0x6c636f72, leftCorner, 0x11, 0x1bd, 0x20, 0x1e, 1, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    leftCorner->SetPictureResourceIdAndRefresh(0x939, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TNoHilitePicture* rightCorner = new TNoHilitePicture();
    RegisterUiResourceEntry(kControlTagPict, 0x72636f72, rightCorner, 0x24e, 0x1bd, 0x20, 0x1e, 1,
                            1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    rightCorner->SetPictureResourceIdAndRefresh(0x93a, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TDropShadowText* titleText1 = new TDropShadowText();
    RegisterUiResourceEntry(0x73746174, 0x74746c31, titleText1, 0x43, 0x28, 0x80, 0x10, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TDropShadowText* titleText2 = new TDropShadowText();
    RegisterUiResourceEntry(0x73746174, 0x74746c32, titleText2, 0xf0, 0x28, 0x80, 0x10, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TDropShadowText* titleText3 = new TDropShadowText();
    RegisterUiResourceEntry(0x73746174, 0x74746c33, titleText3, 0x188, 0x28, 0x80, 0x10, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TInfoBarText* cursorInfoText = new TInfoBarText();
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorInfoText, 0x182, 5, 0xc9, 0x1e,
                            0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    g_pUiResourceContext = 0;
  } else {
    if (static_cast<short>(nEventCode) != 0x942) {
      return 0;
    }

    TWindow* window = new TWindow();
    g_pUiResourceContext = window;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = window;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(window);
    offset[0] = 0x97;
    offset[1] = 0x80;
    size[0] = 0x168;
    size[1] = 0x127;
    window->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    window->controlTag = static_cast<int>(kControlTagWind);
    window->field3c = 0;
    window->SetEnabled(1, 0);
    window->SetState(1, 0);
    window->flag4c = 1;
    window->flag4d = 1;
    window->field70 = 0;
    window->flag6f = 1;
    window->flag6e = 1;
    window->field6d = 0;
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
    g_UiWidgetBuildStack006a13e0.AddTail(goldView);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x168;
    size[1] = 0x127;
    goldView->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    goldView->controlTag = static_cast<int>(kControlTagGold);
    goldView->field3c = 0;
    goldView->SetEnabled(1, 0);
    goldView->SetState(0, 0);
    goldView->flag4c = 1;
    goldView->flag4d = 1;
    g_pUiResourceContext = 0;

    TPicture* topPicture = new TPicture();
    g_pUiResourceContext = topPicture;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = topPicture;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(topPicture);
    offset[0] = 0;
    offset[1] = 0;
    size[0] = 0x168;
    size[1] = 0x127;
    topPicture->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    topPicture->controlTag = static_cast<int>(0x746f7020); // 'top ' (see MISSING-TAG)
    topPicture->field3c = 0;
    topPicture->SetEnabled(1, 0);
    topPicture->SetState(0, 0);
    topPicture->flag4c = 1;
    topPicture->flag4d = 1;
    topPicture->hasCommandTagResource = 0xa;
    topPicture->field68 = 0;
    topPicture->field6C = 0;
    topPicture->field70 = 0;
    topPicture->field74 = 0;
    topPicture->SetPictureResourceIdAndRefresh(0x942, 0);
    g_pUiResourceContext = 0;

    TDropShadowText* titleText = new TDropShadowText();
    g_pUiResourceContext = titleText;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = titleText;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(titleText);
    offset[0] = 0x51;
    offset[1] = 0x13;
    size[0] = 0x108;
    size[1] = 0x20;
    titleText->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    titleText->controlTag = static_cast<int>(0x7469746c); // 'titl' (see MISSING-TAG)
    titleText->field3c = 0;
    titleText->SetEnabled(1, 0);
    titleText->SetState(0, 0);
    titleText->flag4c = 1;
    titleText->flag4d = 1;
    titleText->hasCommandTagResource = 0xd;
    titleText->field68 = 0;
    titleText->field6C = 0;
    titleText->field70 = 0;
    titleText->field74 = 0;
    BindUiResourceTextAndStyle(0x3e9, 1, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TPicture* patchPicture = new TPicture();
    g_pUiResourceContext = patchPicture;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = patchPicture;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(patchPicture);
    offset[0] = 0xa;
    offset[1] = 0xa;
    size[0] = 0x3c;
    size[1] = 0x3c;
    patchPicture->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    patchPicture->controlTag = static_cast<int>(kControlTagPict);
    patchPicture->field3c = 0;
    patchPicture->SetEnabled(1, 0);
    patchPicture->SetState(0, 0);
    patchPicture->flag4c = 1;
    patchPicture->flag4d = 1;
    patchPicture->hasCommandTagResource = 0xa;
    patchPicture->field68 = 0;
    patchPicture->field6C = 0;
    patchPicture->field70 = 0;
    patchPicture->field74 = 0;
    patchPicture->SetPictureResourceIdAndRefresh(0x945, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TScrollView* scrollView = new TScrollView();
    g_pUiResourceContext = scrollView;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = scrollView;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(scrollView);
    offset[0] = 9;
    offset[1] = 0x4c;
    size[0] = 0x156;
    size[1] = 0xaf;
    scrollView->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    scrollView->controlTag = static_cast<int>(0x73637677); // 'scvw' (see MISSING-TAG)
    scrollView->field3c = 0;
    scrollView->SetEnabled(1, 0);
    scrollView->SetState(0, 0);
    scrollView->flag4c = 1;
    scrollView->flag4d = 1;
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();

    TUpDownPictureButton* okayButton = new TUpDownPictureButton();
    g_pUiResourceContext = okayButton;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = okayButton;
      parent = 0;
    }
    g_UiWidgetBuildStack006a13e0.AddTail(okayButton);
    offset[0] = 0x119;
    offset[1] = 0x104;
    size[0] = 0x3d;
    size[1] = 0x18;
    okayButton->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
    okayButton->controlTag = static_cast<int>(kControlTagOkay);
    okayButton->field3c = 0;
    okayButton->SetEnabled(1, 0);
    okayButton->SetState(1, 0);
    okayButton->flag4c = 1;
    okayButton->flag4d = 1;
    okayButton->hasCommandTagResource = 0x22;
    okayButton->field68 = 0;
    okayButton->field6C = 0;
    okayButton->field70 = 0;
    okayButton->field74 = 0;
    okayButton->SetPictureResourceIdAndRefresh(0x24c2, 0);
    g_pUiResourceContext = 0;
    g_UiWidgetBuildStack006a13e0.RemoveTail();
  }

  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();
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
      g_UiWidgetBuildStack006a13e0.AddTail(base);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x7d0;
      size[1] = 0x7d0;
      base->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      base->controlTag = static_cast<int>(kControlTagBase);
      base->field3c = 0;
      base->SetEnabled(1, 0);
      base->SetState(0, 0);
      base->flag4c = 1;
      base->flag4d = 1;
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
      g_UiWidgetBuildStack006a13e0.AddTail(main);
      offset[0] = 0;
      offset[1] = 0;
      size[0] = 0x280;
      size[1] = 0x1e0;
      main->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      main->controlTag = static_cast<int>(kControlTagMain);
      main->field3c = 0;
      main->SetEnabled(1, 0);
      main->SetState(0, 0);
      main->flag4c = 1;
      main->flag4d = 1;
      // Inline ReplaceUiResourceContextPairBuffer(0, 0xffffff): the original writes
      // through the fresh field48 without a null re-check - faithful.
      delete main->field48;
      main->field48 = new TUiStyleBytes();
      main->field48->styleWord = 0;
      main->field48->packedColor = 0xffffff;
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
      g_UiWidgetBuildStack006a13e0.AddTail(toolbar);
      offset[0] = 0x258;
      offset[1] = 0x1f;
      size[0] = 0x1e;
      size[1] = 0x2c;
      toolbar->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
      toolbar->controlTag = static_cast<int>(0x74627232); // 'tbr2' (see MISSING-TAG)
      toolbar->field3c = 0;
      toolbar->SetEnabled(1, 0);
      toolbar->SetState(0, 0);
      toolbar->flag4c = 1;
      toolbar->flag4d = 1;
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* cott_5 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f7474 /* 'cott' */, cott_5, 5, 0x95, 0x2a, 0x18,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x526, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* wool_6 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x776f6f6c /* 'wool' */, wool_6, 5, 0xbf, 0x2a, 0x18,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x527, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* food_7 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, kSummaryTagFood, food_7, 0x251, 0xbd, 0x2a, 0x18, 0,
                              1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52c, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TView* mpic_8 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x6d506963 /* 'mPic' */, mpic_8, 0x254, 0x6a,
                              0x23, 0x1a, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* seas_11 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagSeas, seas_11, 0x2c, 4, 0x5e,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* trea_12 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagTrea, trea_12, 0x8d, 4, 0x4b,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_16 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_16, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84e, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_17 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_17, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x850, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_18 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_18, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_19 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_19, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_20 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_20, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_21 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_21, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_24 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_24, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_25 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_25, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_26 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_26, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_27 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_27, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_28 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_28, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_29 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_29, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_32 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_32, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_33 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_33, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_34 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_34, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_35 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_35, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_36 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_36, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_37 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_37, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_40 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_40, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_41 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_41, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_42 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_42, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_43 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_43, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_44 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_44, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_45 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_45, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_48 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_48, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_49 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_49, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_50 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_50, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_51 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_51, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_52 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_52, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_53 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_53, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_56 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_56, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_57 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_57, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_58 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_58, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_59 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_59, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_60 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_60, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_61 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_61, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_64 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_64, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_65 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_65, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_66 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_66, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_67 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_67, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_68 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_68, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_69 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_69, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_72 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_72, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_73 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_73, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_74 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_74, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_75 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_75, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_76 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_76, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_77 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_77, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_80 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_80, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_81 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_81, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_82 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_82, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_83 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_83, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_84 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_84, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_85 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_85, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_88 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_88, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_89 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_89, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_90 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_90, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_91 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_91, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_92 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_92, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_93 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_93, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_96 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_96, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_97 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_97, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_98 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_98, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_99 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_99, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_100 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_100, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_101 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_101, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_104 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_104, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_105 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_105, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_106 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_106, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_107 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_107, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_108 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_108, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_109 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_109, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_112 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_112, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_113 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_113, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_114 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_114, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_115 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_115, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_116 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_116, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_117 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_117, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_120 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_120, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_121 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_121, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_122 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_122, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_123 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_123, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_124 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_124, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_125 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_125, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_128 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_128, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_129 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_129, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_130 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_130, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_131 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_131, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_132 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_132, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_133 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_133, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_136 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_136, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_137 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_137, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_138 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_138, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_139 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_139, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_140 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_140, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_141 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_141, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_144 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_144, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_145 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_145, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_146 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_146, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_147 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_147, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_148 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_148, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_149 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_149, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* topt_150 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x746f7054 /* 'topT' */, topt_150, 0x36,
                              0x25, 0x215, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 1, g_szUiBoardOfTradeLabel_00694AF8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* comt_151 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x636f6d54 /* 'comT' */, comt_151, 0x30,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 2, g_szUiCommodityLabel_00694AEC, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* ordt_152 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6f726454 /* 'ordT' */, ordt_152, 0x8a,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 3, g_szUiOrdersLabel_006948A4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TStaticText* prit_153 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x70726954 /* 'priT' */, prit_153, 0xf0,
                              0x49, 0x43, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 4, g_szUiPriceLabel_00694AE4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TStaticText* avat_154 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x61766154 /* 'avaT' */, avat_154, 0x136,
                              0x49, 0x48, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 5, g_szUiAvailableLabel_00694AD8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TStaticText* qtyt_155 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x71747954 /* 'qtyT' */, qtyt_155, 0x182,
                              0x49, 0xb5, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiQuantityToOfferLabel_00694AC0, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TUpDownPictureButton* city_158 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCity, city_158, 0x1f, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24ed, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TUpDownPictureButton* trad_159 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagTrad, trad_159, 0x3b, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24eb, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TUpDownPictureButton* dipl_160 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagDipl, dipl_160, 0x58, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24e9, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TInfoBarText* curs_161 = new TInfoBarText();
      RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, curs_161, 0x182, 5, 0xc9, 0x1e, 0,
                              1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* timb_162 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x74696d62 /* 'timb' */, timb_162, 5, 0xe7, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x528, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* coal_163 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f616c /* 'coal' */, coal_163, 5, 0x110, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x529, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* iron_164 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x69726f6e /* 'iron' */, iron_164, 5, 0x13c, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52a, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* oil_165 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6f696c20 /* 'oil ' */, oil_165, 5, 0x164, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* fabr_166 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x66616272 /* 'fabr' */, fabr_166, 0x251, 0xe6, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52d, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* lumb_167 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6c756d62 /* 'lumb' */, lumb_167, 0x251, 0x112,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52e, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* stee_168 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x73746565 /* 'stee' */, stee_168, 0x251, 0x138,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52f, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_7 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_7, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84e, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_8 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_8, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x850, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_9 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_9, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_10 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_10, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_11 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_11, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_12 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_12, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643020 /* 'gd0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_15 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_15, 0x52, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_16 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_16, 0xa3, 0, 0x11, 0x14, 0, 0,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_17 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_17, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_18 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_18, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_19 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_19, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_20 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_20, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643120 /* 'gd1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_23 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_23, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_24 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_24, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_25 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_25, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_26 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_26, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_27 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_27, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_28 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_28, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643220 /* 'gd2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_31 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_31, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_32 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_32, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_33 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_33, 0x18f, 6, 0x64, 7, 0, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_34 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_34, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_35 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_35, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_36 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_36, 0x18f, 7, 0x64, 7, 1,
                              1, 0x67643320 /* 'gd3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_39 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_39, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_40 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_40, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_41 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_41, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_42 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_42, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_43 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_43, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_44 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_44, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613220 /* 'ma2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_47 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_47, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_48 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_48, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_49 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_49, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_50 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_50, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_51 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_51, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_52 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_52, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613320 /* 'ma3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_55 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_55, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_56 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_56, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_57 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_57, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_58 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_58, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_59 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_59, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_60 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_60, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613120 /* 'ma1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_63 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_63, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_64 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_64, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x842, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_65 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_65, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_66 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_66, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_67 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_67, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_68 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_68, 0x18f, 7, 0x64, 7, 1,
                              1, 0x6d613020 /* 'ma0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_71 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_71, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_72 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_72, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_73 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_73, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_74 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_74, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_75 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_75, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_76 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_76, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733420 /* 'rs4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_79 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_79, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_80 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_80, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_81 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_81, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_82 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_82, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_83 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_83, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_84 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_84, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733520 /* 'rs5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_87 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_87, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_88 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_88, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_89 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_89, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_90 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_90, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_91 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_91, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_92 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_92, 0x18f, 7, 0x64, 7, 1,
                              1, 0x72733320 /* 'rs3 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_95 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_95, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_96 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_96, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_97 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_97, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_98 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_98, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_99 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_99, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_100 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_100, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733220 /* 'rs2 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_103 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_103, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_104 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_104, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_105 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_105, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_106 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_106, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_107 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_107, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_108 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_108, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733120 /* 'rs1 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_111 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_111, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_112 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_112, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_113 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_113, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_114 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_114, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_115 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_115, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_116 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_116, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733020 /* 'rs0 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_119 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_119, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_120 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_120, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_121 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_121, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_122 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_122, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_123 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_123, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_124 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_124, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613520 /* 'ma5 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_127 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_127, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_128 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_128, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_129 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_129, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_130 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_130, 0x18f, 6, 0x64, 7, 0, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_131 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_131, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_132 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_132, 0x18f, 7, 0x64, 7,
                              1, 1, 0x6d613420 /* 'ma4 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* card_135 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCard, card_135, 0x52, 0, 0x10, 0x12, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x840, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTradeOrderPicture* offr_136 = new TTradeOrderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagOffr, offr_136, 0xa3, 0, 0xe, 0x13, 0, 0,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x841, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* left_137 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowLeft, left_137, 0x17f, 5, 0x10, 0xa, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x849, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSliderPicture* gree_138 = new TSliderPicture();
      RegisterUiResourceEntry(kControlTagPict, kControlTagGree, gree_138, 0x18f, 6, 0x64, 7, 0, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x848, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TSidewaysArrow* rght_139 = new TSidewaysArrow();
      RegisterUiResourceEntry(kControlTagPict, kTagArrowRight, rght_139, 0x1f2, 5, 0xf, 0xb, 1, 1,
                              0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x84b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TTraderAmtBar* bar_140 = new TTraderAmtBar();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBar, bar_140, 0x18f, 7, 0x64, 7,
                              1, 1, 0x72733620 /* 'rs6 ' */, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* topt_141 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x746f7054 /* 'topT' */, topt_141, 0x36,
                              0x25, 0x215, 0x14, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 1, g_szUiBoardOfTradeLabel_00694AF8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* comt_142 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x636f6d54 /* 'comT' */, comt_142, 0x30,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 2, g_szUiCommodityLabel_00694AEC, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* ordt_143 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x6f726454 /* 'ordT' */, ordt_143, 0x8a,
                              0x49, 0x5a, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 3, g_szUiOrdersLabel_006948A4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TStaticText* prit_144 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x70726954 /* 'priT' */, prit_144, 0xf0,
                              0x49, 0x43, 0x17, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 4, g_szUiPriceLabel_00694AE4, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TStaticText* avat_145 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x61766154 /* 'avaT' */, avat_145, 0x136,
                              0x49, 0x48, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 5, g_szUiAvailableLabel_00694AD8, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TStaticText* qtyt_146 = new TStaticText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, 0x71747954 /* 'qtyT' */, qtyt_146, 0x182,
                              0x49, 0xb5, 0x15, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0x5e5, 6, g_szUiQuantityToOfferLabel_00694AC0, 0, 0, 0, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* seas_149 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagSeas, seas_149, 0x2c, 4, 0x5e,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TDropShadowText* trea_150 = new TDropShadowText();
      RegisterUiResourceEntry(0x73746174 /* 'stat' */, kControlTagTrea, trea_150, 0x8d, 4, 0x4b,
                              0x11, 0, 1, kControlTagTool, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
      BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TView* mpic_151 = new TView();
      RegisterUiResourceEntry(0x76696577 /* 'view' */, 0x6d506963 /* 'mPic' */, mpic_151, 0x254,
                              0x6a, 0x23, 0x1a, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* cott_153 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f7474 /* 'cott' */, cott_153, 5, 0x95, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x526, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* wool_154 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x776f6f6c /* 'wool' */, wool_154, 5, 0xbf, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x527, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* food_155 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, kSummaryTagFood, food_155, 0x251, 0xbd, 0x2a, 0x18,
                              0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52c, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* timb_156 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x74696d62 /* 'timb' */, timb_156, 5, 0xe7, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x528, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* coal_157 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x636f616c /* 'coal' */, coal_157, 5, 0x110, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x529, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* iron_158 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x69726f6e /* 'iron' */, iron_158, 5, 0x13c, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52a, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* oil_159 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6f696c20 /* 'oil ' */, oil_159, 5, 0x164, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52b, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* fabr_160 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x66616272 /* 'fabr' */, fabr_160, 0x251, 0xe6, 0x2a,
                              0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52d, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* lumb_161 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x6c756d62 /* 'lumb' */, lumb_161, 0x251, 0x112,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52e, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TPicture* stee_162 = new TPicture();
      RegisterUiResourceEntry(kControlTagPict, 0x73746565 /* 'stee' */, stee_162, 0x251, 0x138,
                              0x2a, 0x18, 0, 1, kControlTagMain, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x52f, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TUpDownPictureButton* city_165 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagCity, city_165, 0x1f, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24ed, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TUpDownPictureButton* trad_166 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagTrad, trad_166, 0x3b, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24eb, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    {
      TUpDownPictureButton* dipl_167 = new TUpDownPictureButton();
      RegisterUiResourceEntry(kControlTagPict, kControlTagDipl, dipl_167, 0x58, 3, 0xe, 0x12, 1, 1,
                              kControlTagBpot, 0);
      SetUiResourceStateFlags(1, 1);
      SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
      static_cast<TPicture*>(g_pUiResourceContext)->SetPictureResourceIdAndRefresh(0x24e9, 0);
      g_pUiResourceContext = 0;
    }
    g_UiWidgetBuildStack006a13e0.RemoveTail();
    g_UiWidgetBuildStack006a13e0.RemoveTail();
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

  g_UiWidgetBuildStack006a13e0.RemoveTail();
  g_UiWidgetBuildStack006a13e0.RemoveTail();
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

// FUNCTION: IMPERIALISM 0x004749a0
TView* __cdecl BuildUniversityDialogShell(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
}
