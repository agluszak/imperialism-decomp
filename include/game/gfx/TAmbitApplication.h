#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/ui_core/TApplication.h"

class TMapUberUberPicture;
class TStream;
class TWindow;

// 0x00493250 — timeGetTime() / 16; the game's coarse UI tick unit, used broadly across
// unrelated view classes for edge-scroll and animation timing.
unsigned int GetTickCountDiv16();

// Ambit-specific application subclass (size 0x54, base TApplication = 0x48) — the
// game-side UI root controller (g_pAmbitApplication), created by
// ImperialismApp::InitInstance. Mirrors MacApp's TAmbitApplication: it owns the manager
// singleton graph (IAmbitApplication) and adds cursor/window virtuals in
// slots 0x2b-0x2d beyond the TApplication vtable.
// VTABLE: IMPERIALISM 0x0063e398
class TAmbitApplication : public TApplication {
public:
  TAmbitApplication() : TApplication() {
    edgeScrollTarget48 = 0;
    dispatchBusyFlag4c = 0;
    languagePackId50 = 0;
  }

  virtual ~TAmbitApplication() override;

  DECLARE_DYNCREATE(TAmbitApplication)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05, 0x0049e2f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06, 0x0049e280
  virtual void Free() override;                    // slot 0x07, 0x0049e1a0

  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12, 0x0049e4b0

  // New virtuals beyond TApplication (slots 0x2b-0x2d; the base vtable ends at 0x2a).
  // MacApp TAmbitApplication::HandleCursor(CPoint, Region**).
  virtual void HandleCursor(int x, int y, void* cursorRegion); // slot 0x2b, 0x0049e320
  // Mac-oracle name DoSetupMenus() — Windows no-op (tentative attribution).
  virtual void DoSetupMenus(); // slot 0x2c, 0x00414770
  // MacApp TAmbitApplication::CloseAndFreeWindow(TWindow*).
  virtual void CloseAndFreeWindow(TWindow* window); // slot 0x2d, 0x0049e4e0

  // Startup: builds the singleton manager graph (TLanguageMgr/TSimMgr/TAssetMgr/
  // TViewMgr/TDisplayMgr/TMacViewMgr/THelpMgr/TMultiplayerMgr). __thiscall on the
  // fresh TAmbitApplication (writes this+0x48/+0x50); previously mis-modeled as the
  // free function InitializeGlobalRuntimeSystemsFromConfig.
  void IAmbitApplication(); // 0x49ded0

  // 0x48 — receiver of HandleCursor's viewport-edge auto-scroll dispatch
  // (Scroll, slot 0x74). Cleared by IAmbitApplication and the
  // map pictures' Free; set to the active map picture by the slot-0x37 lifecycle hook
  // (TMapUberUberPicture::DoPostCreate 0x596810 and the TMapUberPicture override).
  TMapUberUberPicture* edgeScrollTarget48;
  // 0x4c — a busy/dispatch-in-progress byte, set to 1 across many turn-event dispatch
  // branches in TViewMgr's state machine (0x5d7240) and cleared to 0 once handling
  // completes; ground truth confirms a byte-sized write (`MOV byte ptr [EAX+0x4c],1`),
  // not the full int this was previously modeled as.
  unsigned char dispatchBusyFlag4c;
  unsigned char pad4d[3];
  // 0x50 — language pack id (copied from theApp.languagePackIdE4; serialized in
  // saves, with a hardcoded legacy value for formats older than 0x2a).
  int languagePackId50;
};
ASSERT_SIZE(TAmbitApplication, 0x54);
