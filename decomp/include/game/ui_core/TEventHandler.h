#pragma once

#include "compat.h"
#include "game/ui_tags_common.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/app/TObject.h"

class CArchive;
class TView;
class TWindow;
class TControl;
class TEvent;
class TBehavior;
struct TToolboxEvent;

// VTABLE: IMPERIALISM 0x006497a0
class TEventHandler : public TObject {
public:
  int enabled;
  int viewEnabled; // TView::Show state; TWindow::Show mirrors visibility here
  TEventHandler* nextHandler;
  int idleFrequencyTicks;
  int lastIdleTick;
  TBehavior* firstBehavior;
  int controlTag;

  void CopyHandlerFieldsFrom(const TEventHandler* source);

  TEventHandler();
  TEventHandler(const TEventHandler& source)
      : enabled(source.enabled), viewEnabled(source.viewEnabled), nextHandler(source.nextHandler),
        controlTag(source.controlTag) {}

  void HandleIdle(int idlePhase);

  void IEventHandler(TEventHandler* nextHandler);

  DECLARE_DYNCREATE(TEventHandler)
  // FUNCTION: IMPERIALISM 0x0048a160
  virtual ~TEventHandler() override {}
  void Free() override;
  TObject* ShallowClone() override; // 0x08 0x48a7c0 base; TView override
  virtual char IsEnabled();
  virtual void SetEnable(char enabled);
  virtual TEventHandler* GetNextHandler();
  virtual void DispatchQueuedUiCommandAndRelease(void* payload);
  virtual void DispatchUiSelectionToHandler(void* payload);
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event);
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event); // 0x10 0x48a2e0 DoEvent
  virtual void DoMenuCommand(int commandId);
  virtual void DoKeyEvent(TToolboxEvent* event);
  virtual bool DoIdle(int action); // 0x13 0x48a480 (MacApp DoIdle)

  void HandleMenuCommand(int command);
  void HandleKeyEvent(TToolboxEvent* event);
  virtual int GetIdleFreq();
  virtual void SetIdleFreq(int value);
  virtual TWindow* GetWindow();
  virtual bool WantsToBeTarget();
  virtual bool WillingToResignTarget();
  virtual void ResignedTarget();
  virtual void TargetValidationFailed(int reason);
  virtual void TargetValidationSucceeded();
  virtual void BecameWindowTarget();
  virtual void ResignedWindowTarget();
  virtual void BecameTarget();
  virtual bool BecomeTarget();
  virtual bool ResignTarget();
  virtual void SelectOwner(unsigned char select);
  virtual bool IsTarget();
  virtual void RemoveBehavior(TBehavior* behavior);
  virtual void AddBehavior(TBehavior* behavior);
};
ASSERT_SIZE(TEventHandler, 0x20);

void QueueDeferredUiEventPacket(TView* owner, int commandId, TView* control);
