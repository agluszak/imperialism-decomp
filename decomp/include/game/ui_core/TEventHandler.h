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
  int viewEnabled; // +0x08 -- TView::Show state; TWindow::Show mirrors visibility here
  TEventHandler* nextHandler;
  int idleFrequencyTicks;
  int lastIdleTick;
  TBehavior* firstBehavior;
  int controlTag; // 0x1c

  void CopyHandlerFieldsFrom(const TEventHandler* source);

  TEventHandler();
  TEventHandler(const TEventHandler& source)
      : TObject(), enabled(source.enabled), viewEnabled(source.viewEnabled),
        nextHandler(source.nextHandler), controlTag(source.controlTag) {}

  void HandleIdle(int idlePhase);

  void IEventHandler(TEventHandler* nextHandler);

  DECLARE_DYNCREATE(TEventHandler)
  // FUNCTION: IMPERIALISM 0x0048a160
  virtual ~TEventHandler() override {}     // 0x01
  void Free() override;                    // 0x07 0x48a1b0
  TObject* ShallowClone() override;        // 0x08 0x48a7c0 base; TView override 0x48bfd0
  virtual char IsEnabled();                // 0x0a 0x48a240
  virtual void SetEnable(char enabled);    // 0x0b 0x48a260
  virtual TEventHandler* GetNextHandler(); // 0x0c 0x48a2c0
  virtual void DispatchQueuedUiCommandAndRelease(void* payload); // 0x0d 0x48a3b0
  virtual void DispatchUiSelectionToHandler(void* payload);      // 0x0e 0x48a3f0
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event); // 0x0f 0x48a280
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event);       // 0x10 0x48a2e0 DoEvent
  virtual void DoMenuCommand(int command);       // 0x11 0x48a310
  virtual void DoKeyEvent(TToolboxEvent* event); // 0x12 0x48a380
  virtual bool DoIdle(int action);               // 0x13 0x48a480 (MacApp DoIdle)

  void HandleMenuCommand(int command);              // 0x0048a340 -> slot 0x11
  void HandleKeyEvent(TToolboxEvent* event);        // 0x0048a360 -> slot 0x12
  virtual int GetIdleFreq();                        // 0x14 0x415d50
  virtual void SetIdleFreq(int frequency);          // 0x15 0x415d70
  virtual TWindow* GetWindow();                     // 0x16
  virtual bool WantsToBeTarget();                   // 0x17 0x48a530
  virtual bool WillingToResignTarget();             // 0x18 0x48a550
  virtual void ResignedTarget();                    // 0x19 0x48a690
  virtual void TargetValidationFailed(int reason);  // 0x1a 0x48a6b0
  virtual void TargetValidationSucceeded();         // 0x1b 0x48a650
  virtual void BecameWindowTarget();                // 0x1c 0x48a6d0
  virtual void ResignedWindowTarget();              // 0x1d 0x48a670
  virtual void BecameTarget();                      // 0x1e 0x48a6f0
  virtual bool BecomeTarget();                      // 0x1f 0x48a570
  virtual bool ResignTarget();                      // 0x20 0x48a5e0
  virtual void SelectOwner(unsigned char select);   // 0x21 0x48a710
  virtual bool IsTarget();                          // 0x22 0x48a500
  virtual void RemoveBehavior(TBehavior* behavior); // 0x23 0x48a4a0
  virtual void AddBehavior(TBehavior* behavior);    // 0x24 0x48a4d0
};
ASSERT_SIZE(TEventHandler, 0x20);

void QueueDeferredUiEventPacket(TView* owner, int commandId, TView* control);
