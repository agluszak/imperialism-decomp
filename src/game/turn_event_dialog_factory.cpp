#include "game/turn_event_dialog_factory.h"

#include "game/TBook.h"
#include "game/TDeluxeText.h"
#include "game/TDropShadowText.h"
#include "game/TNoHilitePicture.h"
#include "game/TPageView.h"
#include "game/TScrollView.h"
#include "game/TTechHistoryView.h"
#include "game/TGameWindow.h"
#include "game/TInfoBarText.h"
#include "game/TPicture.h"
#include "game/TPictureButton.h"
#include "game/TStaticText.h"
#include "game/TToolBarCluster.h"
#include "game/TMovieView.h"
#include "game/TUpDownPictureButton.h"
#include "game/TView.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_resource_pool.h"

namespace {

// The original build emits CList<void*,void*>::AddTail on g_UiWidgetBuildStack out-of-line
// (the 0x479b00 template COMDAT) and *calls* it from each builder; routing the append through
// this non-inline wrapper reproduces that call rather than inlining AddTail into every builder
// (which would inflate the builder's stack frame and cascade all stack offsets).
void PushUiWidgetBuildStackNode(void* node) {
  g_UiWidgetBuildStack006a13e0.AddTail(node);
}
void PopUiWidgetBuildStackNode() {
  g_UiWidgetBuildStack006a13e0.RemoveTail();
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
    PushUiWidgetBuildStackNode(background);

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
      PushUiWidgetBuildStackNode(movie);

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
  PushUiWidgetBuildStackNode(window);
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
  PushUiWidgetBuildStackNode(goldPanel);
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
  PushUiWidgetBuildStackNode(okayButton);
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
  PopUiWidgetBuildStackNode();

  TPicture* rewardPicture = new TPicture();
  g_pUiResourceContext = rewardPicture;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = rewardPicture;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(rewardPicture);
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
  PopUiWidgetBuildStackNode();

  TPicture* coatPicture = new TPicture();
  RegisterUiResourceEntry(kControlTagPict, kControlTagCoat, coatPicture, 0x127, 0xc, 0x54, 0x7d, 0,
                          1, kControlTagGold, 0);
  coatPicture->flag4c = 1;
  coatPicture->flag4d = 1;
  SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
  coatPicture->SetPictureResourceIdAndRefresh(0x251c, 0);
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  TDeluxeText* infoText = new TDeluxeText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagInfo, infoText, 0x11, 0xa0, 0x162, 0x54, 0, 1,
                          kControlTagGold, 0);
  infoText->flag4c = 1;
  infoText->flag4d = 0;
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

// FUNCTION: IMPERIALISM 0x004538a0
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
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
  PushUiWidgetBuildStackNode(baseContainer);
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
  PushUiWidgetBuildStackNode(mainPicture);
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
  PushUiWidgetBuildStackNode(bodyText);
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
  PopUiWidgetBuildStackNode();

  TToolBarCluster* toolbar = new TToolBarCluster();
  g_pUiResourceContext = toolbar;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = toolbar;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(toolbar);
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
  PushUiWidgetBuildStackNode(endButton);
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
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();

  TInfoBarText* cursorInfoText = new TInfoBarText();
  RegisterUiResourceEntry(kControlTagTevw, kControlTagCrus, cursorInfoText, 0xf7, 7, 0x155, 0x11, 0,
                          1, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 0);
  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  TPicture* patchPicture = new TPicture();
  RegisterUiResourceEntry(kControlTagPict, kControlTagPatc, patchPicture, 0x248, 0x23, 0x34, 0x48,
                          0, 1, kControlTagMain, 0);
  SetUiResourceStateFlags(1, 1);
  SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
  patchPicture->SetPictureResourceIdAndRefresh(0x8b6, 0);
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
  if (static_cast<short>(nEventCode) == 0x8fc) {
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
    PushUiWidgetBuildStackNode(mainBook);
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
    PushUiWidgetBuildStackNode(toolbar);
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
    PushUiWidgetBuildStackNode(endButton);
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
    PushUiWidgetBuildStackNode(transportButton);
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
    PushUiWidgetBuildStackNode(queryButton);
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
    PopUiWidgetBuildStackNode();
    PopUiWidgetBuildStackNode();

    TPageView* pageView = new TPageView();
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
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCrus, cursorInfoText, 0x182, 5, 0xc9, 0x1e,
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
    PushUiWidgetBuildStackNode(window);
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
    PushUiWidgetBuildStackNode(goldView);
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
    PushUiWidgetBuildStackNode(topPicture);
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
    PushUiWidgetBuildStackNode(titleText);
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
    PopUiWidgetBuildStackNode();

    TScrollView* scrollView = new TScrollView();
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
    scrollView->field3c = 0;
    scrollView->SetEnabled(1, 0);
    scrollView->SetState(0, 0);
    scrollView->flag4c = 1;
    scrollView->flag4d = 1;
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
    PopUiWidgetBuildStackNode();
  }

  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  PopUiWidgetBuildStackNode();
  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}

// FUNCTION: IMPERIALISM 0x004601b0
TView* __cdecl InitializeTradeScreenBitmapControls(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
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
