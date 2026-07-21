#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TCommandHandler.h"
#include "game/global_data_tables.h"
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
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48a1b0)
  // slot 0x08 ShallowClone inherited unchanged (0x48a7c0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IsEnabled inherited unchanged (0x48a240)
  // slot 0x0b SetEnable inherited unchanged (0x48a260)
  // slot 0x0c GetNextHandler inherited unchanged (0x48a2c0)
  // Windows override: post the queued command pointer to the main-frame 0xBC0 handler.
  virtual void DispatchQueuedUiCommandAndRelease(void* payload) override; // slot 0x0d 0x486b50
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f DoEvent inherited unchanged (0x48a280)
  // slot 0x10 HandleEvent inherited unchanged (0x48a2e0)
  virtual void DoMenuCommand(int param) override; // slot 0x11 0x486ba0
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  // slot 0x13 DoIdle inherited unchanged (0x48a480)
  // slot 0x14 GetIdleFreq inherited unchanged (0x415d50)
  // slot 0x15 SetIdleFreq inherited unchanged (0x415d70)
  // slot 0x16 GetWindow inherited unchanged (0x48a730)
  // slot 0x17 WantsToBeTarget inherited unchanged (0x48a530)
  // slot 0x18 WillingToResignTarget inherited unchanged (0x48a550)
  // slot 0x19 ResignedTarget inherited unchanged (0x48a690)
  // slot 0x1a TargetValidationFailed inherited unchanged (0x48a6b0)
  // slot 0x1b TargetValidationSucceeded inherited unchanged (0x48a650)
  // slot 0x1c BecameWindowTarget inherited unchanged (0x48a6d0)
  // slot 0x1d ResignedWindowTarget inherited unchanged (0x48a670)
  // slot 0x1e BecameTarget inherited unchanged (0x48a6f0)
  // slot 0x1f BecomeTarget inherited unchanged (0x48a570)
  // slot 0x20 ResignTarget inherited unchanged (0x48a5e0)
  // slot 0x21 SelectOwner inherited unchanged (0x48a710)
  // slot 0x22 IsTarget inherited unchanged (0x48a500)
  // slot 0x23 RemoveBehavior inherited unchanged (0x48a4a0)
  // slot 0x24 AddBehavior inherited unchanged (0x48a4d0)
  // slot 0x25 PerformCommand inherited unchanged (0x486650)
  virtual void SetTarget(TEventHandler* view); // slot 0x26 0x486880
  virtual TEventHandler* GetTarget();          // slot 0x27 0x4868a0
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
