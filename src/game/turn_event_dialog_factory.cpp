#include "game/turn_event_dialog_factory.h"

#include "game/TDeluxeText.h"
#include "game/TDropShadowText.h"
#include "game/TGameWindow.h"
#include "game/TInfoBarText.h"
#include "game/TPicture.h"
#include "game/TPictureButton.h"
#include "game/TStaticText.h"
#include "game/TToolBarCluster.h"
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
    delete[] window->field48;
    window->field48 = 0;
  }
  window->EnsureField48Buffer();
  if (window->field48 != 0) {
    ZeroUiResourceContextStyleBytes(reinterpret_cast<unsigned char*>(window->field48));
    window->field48[1] = 0;
    window->field48[0] = 0xffffff;
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
// KNOWN INCOMPLETE — does not yet render on screen. Shortcuts taken while porting this:
//
// TODO(shortcut): only the container + background picture are ported. The real
// 0x0043b1cb case continues past this (building at least one more object, a 0x94-byte
// TMovieView per its ctor address 0x5e2230) that was not traced/ported — TMovieView
// itself is still all stub method bodies (src/game/TMovieView.cpp). Unknown whether the
// missing piece is load-bearing for this screen to actually display.
//
// TODO(shortcut): the "panel" argument passed to InitializeUiResourceEntryFrameAndParent
// is hardcoded 0 for both widgets. The real disassembly reads the build-stack tail
// (g_UiWidgetBuildStack006a13e0's last node, the enclosing widget being built) as each
// new widget's parent panel — see RegisterUiResourceEntry and
// BuildTurnEventDialogResources_2508 for the decoded pattern. Passing 0 means this tree
// never inherits nativeWindow50 through the normal per-widget mechanism at all;
// nativeWindow50 is instead force-set by hand below via
// PropagateUiResourceContextRecursive(mainNativeWindow), which is NOT something the
// original does at this point (verified: the original's g_pUiResourceHead->
// PropagateUiResourceContextRecursive call elsewhere in this file, in
// BuildTurnOrderNavigationWindow, passes literal 0/null — this factory diverges from
// that on purpose as an experiment, and it did not fix on-screen rendering).
//
// Empirically confirmed via live winedbg + X11 screenshot capture this session:
//   - Before the PropagateUiResourceContextRecursive(mainNativeWindow) change: the
//     built tree rendered into a separate ~550x357 transient popup window (title bitmap
//     visibly correct), not the main frame — that popup no longer appears after the
//     change.
//   - After the change: no crash, no popup, but the main frame's client area stays
//     blank. The real trigger for repainting newly-attached content — believed to be
//     TIncludeView::NoOpUiLifecycleHook's tail `SendMessageA(hwnd, 0x4ef, 1, 0)` (already
//     ported) reaching some message-map handler not yet identified — was not found.
//     TView::RefreshControl() was tried directly from here and is a confirmed no-op:
//     g_McAppUiActiveFlag_006950AC is deliberately 0 for the whole duration of
//     TTurnEventDialogFactoryRegistry::InvokeDialogFactoryFromPacket, so any refresh
//     triggered from inside a factory body silently does nothing by design.
TView* BuildStartupIntroBackground() {
  TView* container = new TView();
  if (container == 0) {
    return 0;
  }

  if (g_pUiResourceHead == 0) {
    g_pUiResourceHead = container;
  }
  g_pUiResourceContext = container;

  g_UiWidgetBuildStack006a13e0.AddTail(container);

  int containerOffset[2] = {0, 0};
  int containerSize[2] = {0x7d0, 0x7d0};
  container->InitializeUiResourceEntryFrameAndParent(0, 0, containerOffset, containerSize, 0, 0, 1);
  container->controlTag = static_cast<int>(kControlTagBase);
  container->field3c = 0;
  container->SetEnabled(1, 0);
  container->SetState(containerSize[0], 0);

  TPicture* background = new TPicture();
  if (background != 0) {
    g_pUiResourceContext = background;

    int pictureOffset[2] = {0, 0};
    int pictureSize[2] = {0x280, 0x1e0};
    background->InitializeUiResourceEntryFrameAndParent(0, 0, pictureOffset, pictureSize, 0, 0, 1);
    background->controlTag = static_cast<int>(kControlTagMain);
    background->field3c = 0;
    background->SetEnabled(1, 0);
    background->SetState(pictureSize[0], 0);
    container->AttachChildControl(background, 0);

    background->EnsureField48Buffer();
    if (background->field48 != 0) {
      background->field48[1] = 0;
      background->field48[0] = 0xffffff;
    }

    background->hasCommandTagResource = 0xa;
    background->field68 = 0;
    background->field6C = 0;
    background->field70 = 0;

    background->SetPictureResourceIdAndRefresh(0x11f7, 0);
  }

  g_pUiResourceContext = 0;
  g_UiWidgetBuildStack006a13e0.RemoveTail();

  // Unlike BuildTurnOrderNavigationWindow's TGameWindow (which gets its own native host
  // window later via TWindow::Realize), this tree is plain TView/TPicture — it has no
  // window of its own and must share the main view's, or nothing ever gets a valid HWND
  // to paint into.
  if (g_pUiResourceHead != 0) {
    CWnd* mainNativeWindow = (g_pDisplayMgr != nullptr && g_pDisplayMgr->activeDialog != nullptr)
                                 ? g_pDisplayMgr->activeDialog->nativeWindow50
                                 : nullptr;
    g_pUiResourceHead->PropagateUiResourceContextRecursive(mainNativeWindow);
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
  int windowOffset[2] = {0x64, 0x50};
  int windowSize[2] = {0x186, 0x11a};
  window->InitializeUiResourceEntryFrameAndParent(0, parent, windowOffset, windowSize, 0, 0, 1);
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
  int goldOffset[2] = {0, 0};
  int goldSize[2] = {0x186, 0x11a};
  goldPanel->InitializeUiResourceEntryFrameAndParent(0, parent, goldOffset, goldSize, 0, 0, 1);
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
  int okayOffset[2] = {0x136, 0xf8};
  int okaySize[2] = {0x3d, 0x17};
  okayButton->InitializeUiResourceEntryFrameAndParent(0, parent, okayOffset, okaySize, 0, 0, 1);
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
  int rewardOffset[2] = {0x70, 0x12};
  int rewardSize[2] = {0xa7, 0x6d};
  rewardPicture->InitializeUiResourceEntryFrameAndParent(0, parent, rewardOffset, rewardSize, 0, 0,
                                                         1);
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
    mainPicture->field48[1] = 0;
    mainPicture->field48[0] = 0xffffff;
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
  RegisterUiResourceEntry(kControlTagTevw, kControlTagCrus, cursorInfoText, 0xf7, 7, 0x155, 0x11, 0,
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

// FUNCTION: IMPERIALISM 0x0045e0b0
TView* __cdecl BuildTurnEventDialogResourcesForEvent8FC(CWnd* pHostWindow, int nEventCode) {
  (void)pHostWindow;
  (void)nEventCode;
  return nullptr;
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
