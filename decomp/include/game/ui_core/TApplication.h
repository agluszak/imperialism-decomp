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
  virtual void DispatchQueuedUiCommandAndRelease(void* payload) override;
  virtual void DoMenuCommand(int command) override;
  virtual void SetTarget(TEventHandler* view);
  virtual TEventHandler* GetTarget();
  // MacApp TApplication::GetDefaultCursorRegion(CPoint, Region**); no-op on Windows.
  virtual void GetDefaultCursorRegion(int x, int y, void* cursorRegion);
  // MacApp TApplication::InstallCohandler(TEventHandler*, Boolean).
  virtual void InstallCohandler(TEventHandler* cohandler, bool install);
  // MacApp TApplication::Idle(IdlePhase): HandleIdle every installed cohandler.
  virtual void Idle(int idlePhase);
  TApplication();

  void CreateAndQueueTurnEventPacketTagGWEN();
  ~TApplication() override;

  void PostTurnEventCodeMessage(TurnEventCodeStorage eventCode);
  void PostWmCloseToMainThreadWindow();

  BOOL InModalState();

  // vtable index 0x00 override (0x00486740): returns the TApplication CRuntimeClass.
  DECLARE_DYNCREATE(TApplication)

  TEventHandler* currentTarget;
  int screenMode;
  BOOL cursorRegionInvalid;
  CList<void*, void*> cohandlers;
};

ASSERT_SIZE(TApplication, 0x48);
