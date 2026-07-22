#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TCommandHandler.h"
#include <afxtempl.h>

// Application UI root controller — global modal-view gatekeeper installed at startup.
// Inherits the shared 37-slot base interface (indices 0x00-0x24) and fields through +0x1c
// from TEventHandler (the same base TView derives from). Introduces its own slots 0x25-0x2a
// (byte offsets 0x94-0xa8): a command-handler dispatch, the target get/set pair, a
// viewport-edge auto-scroll no-op, an intrusive-list insert/remove, and a per-entry tick
// walk over the embedded list at +0x2c (secondary vtable 0x00648ca8). Size 0x48.
// VTABLE: IMPERIALISM 0x00648bd8
class TApplication : public TCommandHandler {
public:
  // Windows override: post the queued command pointer to the main-frame 0xBC0 handler.
  virtual void DispatchQueuedUiCommandAndRelease(void* payload) override; // slot 0x0d 0x486b50
  virtual void DoMenuCommand(int param) override;                         // slot 0x11 0x486ba0
  virtual void SetTarget(TEventHandler* view);                            // slot 0x26 0x486880
  virtual TEventHandler* GetTarget();                                     // slot 0x27 0x4868a0
  // MacApp TApplication::GetDefaultCursorRegion(CPoint, Region**); no-op on Windows.
  virtual void GetDefaultCursorRegion(int x, int y,
                                      void* cursorRegion); // slot 0x28 0x486990
  // MacApp TApplication::InstallCohandler(TEventHandler*, Boolean).
  virtual void InstallCohandler(TEventHandler* cohandler,
                                unsigned char install); // slot 0x29 0x4869b0
  // MacApp TApplication::Idle(IdlePhase): HandleIdle every installed cohandler.
  virtual void Idle(int idlePhase); // slot 0x2a 0x486b10
  TApplication();

  // 0x49e500: build + queue the 'gwen' (game-window-end) turn-event packet through the
  // UI root controller (turn-event 0x1F 'aced'/'lost'/'quit' receive paths).
  void CreateAndQueueTurnEventPacketTagGWEN();
  ~TApplication() override;

  // Post custom message 0x2420 (turn-event code in wParam) to the main frame; handled
  // by CMainFrame::HandleCustomMessage2420DispatchTurnEvent. Does not touch `this`.
  void PostTurnEventCodeMessage2420(short eventCode); // 0x414720

  // MacApp TApplication::InModalState(): TRUE while the main view host's +0x90
  // interactive flag is clear.
  BOOL InModalState(); // 0x486960

  // vtable index 0x00 override (0x00486740): returns the TApplication CRuntimeClass.
  DECLARE_DYNCREATE(TApplication)
  // vtable index 0x27 (0x004868a0): load the current target pointer.

  TEventHandler* currentTarget; // 0x20
  int screenModeAt24;           // 0x24
  // MacApp fCursorRgnInvalid, exposed by IsCursorRgnInvalid()/InvalidateCursorRgn().
  // Windows accesses the BOOL directly when map views open and close.
  BOOL cursorRegionInvalid; // 0x28
  // 0x2c — MacApp fCohandlers: TEventHandlers given idle time by Idle(). Kept as the
  // original CList<void*, void*> instantiation (vtable 0x00648ca8).
  CList<void*, void*> cohandlers;

  // Reserved slots overridden by TAmbitApplication only (orig TApplication vtable has null at
  // 0x2b-0x2d).
};

ASSERT_SIZE(TApplication, 0x48);
