#include "game/TTurnEventDialogFactoryRegistry.h"

#include "game/TGameWindow.h"
#include "game/TPicture.h"
#include "game/TView.h"
#include "game/global_data_tables.h"

extern unsigned char* ZeroUiResourceContextStyleBytes(unsigned char* buffer);

#include "game/ui_control_tags.h"

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

  char* bytes = reinterpret_cast<char*>(window);
  bytes[0x6d] = 0;
  bytes[0x6e] = 1;
  bytes[0x6f] = 1;
  bytes[0x71] = 1;
  *reinterpret_cast<unsigned short*>(bytes + 0x60) = layoutModeWord;
  *reinterpret_cast<unsigned short*>(bytes + 0x9c) = 8;

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
// TODO(shortcut): the picture's border/bevel style fields (TControl's protected
// hasCommandTagResource/field68/field6C/field70) are left at constructor defaults
// instead of being set to the real disassembly's values (0xa, 0, 0, 0) — skipped
// because they're `protected` in TModalTemplateDialogBase and this is a free function,
// not a TControl method. Believed cosmetic (frame decoration only), not verified.
//
// TODO(shortcut): the "panel" argument passed to InitializeUiResourceEntryFrameAndParent
// is hardcoded 0 for both widgets. The real disassembly reads a tracked "current panel"
// global (DAT_006a13e8, read ~20x throughout BuildTurnEventDialogUiByCode) that appears
// to chain each new widget off the previously-built one — not reverse-engineered here.
// Passing 0 means this tree never inherits nativeWindow50 through the normal per-widget
// mechanism at all; nativeWindow50 is instead force-set by hand below via
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
TView* __cdecl BuildTradeSchoolDialogControls(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0041b6d0
TView* __cdecl InitializeIndustryViewTradeMoveControlsAndCommodityRows(int nContextSlot,
                                                                       int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00427360
TView* __cdecl InitializeIndustryOverviewPlacardsAndTradeStatusTags(int nContextSlot,
                                                                    int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004295a0
TView* __cdecl BuildTurnEventDialogResourcesForEvent547Or7D8(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00430c50
TView* __cdecl InitializeDealBookScreenControlsAndCommandTags(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004357b0
TView* __cdecl BuildTurnEventDialogUiByCode(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
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
TView* __cdecl InitializeArmyNavyReportViewsAndCommandTags(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044a810
TView* __cdecl BuildTurnEventDialogResources_2508(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044af90
TView* __cdecl InitializeJoinSelectorDialogControlsAndNationSlots(int nContextSlot,
                                                                  int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0044fbc0
TView* __cdecl BuildUiResourceTreeByTemplateIdAndBindScreenContext(int nContextSlot,
                                                                   int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004538a0
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0045b100
TView* __cdecl InitializeTacticalBattleViewToolbarAndDialogControls(int nContextSlot,
                                                                    int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0045d520
TView* __cdecl BuildTurnEventDialogResourcesForEvent898(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0045e0b0
TView* __cdecl BuildTurnEventDialogResourcesForEvent8FC(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004601b0
TView* __cdecl InitializeTradeScreenBitmapControls(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x0046fd10
TView* __cdecl BuildTurnEventDialogResourcesForEvent7DE(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x004749a0
TView* __cdecl BuildUniversityDialogShell(int nContextSlot, int nEventCode) {
  (void)nContextSlot;
  (void)nEventCode;
  return nullptr;
}
