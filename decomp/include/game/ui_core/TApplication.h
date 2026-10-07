#pragma once

#include "compat.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_core/TCommandHandler.h"
#include "game/turn_event_codes.h"
#include <afxtempl.h>

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
                                bool install); // slot 0x29 0x4869b0
  // MacApp TApplication::Idle(IdlePhase): HandleIdle every installed cohandler.
  virtual void Idle(int idlePhase); // slot 0x2a 0x486b10
  TApplication();

  void CreateAndQueueTurnEventPacketTagGWEN();
  ~TApplication() override;

  void PostTurnEventCodeMessage(TurnEventCodeStorage eventCode); // 0x414720
  void PostWmCloseToMainThreadWindow();                          // 0x4146d0

  BOOL InModalState(); // 0x486960

  // vtable index 0x00 override (0x00486740): returns the TApplication CRuntimeClass.
  DECLARE_DYNCREATE(TApplication)
  // vtable index 0x27 (0x004868a0): load the current target pointer.

  TEventHandler* currentTarget; // 0x20
  int screenMode;               // 0x24
  BOOL cursorRegionInvalid;     // 0x28
  CList<void*, void*> cohandlers;
};

ASSERT_SIZE(TApplication, 0x48);
