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

//
// Shared base of TView and TApplication. Both
// inherit this 37-slot interface (slots 0x00-0x24) and the fields through +0x1c; they
// diverge at +0x20 (TView::ownerContext vs TApplication::activeView) and
// each introduces its own virtuals at slot 0x25+. Proven by vtable comparison: TView
// (0x649858) and TApplication (0x648bd8) share the same body addresses for
// most of slots 0x02-0x24, overriding only a handful. The recovered method names below
// are shared by both branches and must remain signature-identical across overrides.
// VTABLE: IMPERIALISM 0x006497a0
class TEventHandler : public TObject {
public:
  int enabled;
  int viewEnabled; // +0x08 -- TView::SetEnabled state; TWindow::Show mirrors visibility here
  TEventHandler* nextHandler;
  int idleFrequencyTicks;
  int lastIdleTick;
  TBehavior* firstBehavior;
  int controlTag; // 0x1c

  // Copies the same four cloneable fields ShallowClone (0x48a7c0) copies into a fresh
  // header, but into this handler from an existing one. The original writes them in
  // the order 04, 08, 1c, 0c -- ShallowClone uses 04, 08, 0c, 1c -- so the two are
  // separate bodies rather than one shared helper. 0x0048a790, __thiscall.
  void CopyHandlerFieldsFrom(const TEventHandler* source);

  TEventHandler();
  // CObject is intentionally non-copyable in MFC, but this MacApp-derived hierarchy
  // has a real field-copying base constructor inlined into TView's 0x48bd30 copy ctor.
  // Copies exactly the four fields the original copies -- +0x04, +0x08, +0x0c and
  // controlTag at +0x1c -- and no others. idleFrequencyTicks/lastIdleTick are the idle throttle
  // and last-idle stamp and firstBehavior is a list head, none of which a fresh copy
  // inherits.
  // MATCH: keep this in-class; see config/ctor_placement_exceptions.csv.
  // FUNCTION: IMPERIALISM 0x0048a750
  TEventHandler(const TEventHandler& source)
      : TObject(), enabled(source.enabled), viewEnabled(source.viewEnabled),
        nextHandler(source.nextHandler), controlTag(source.controlTag) {}

  // 0x48a410 — MacApp TEventHandler::HandleIdle(IdlePhase); throttled idle dispatch
  // using idleFrequencyTicks (0x7fffffff = never) and lastIdleTick.
  void HandleIdle(int idlePhase);

  // Packet/event-header field initializer (0x48a180, __thiscall).
  // Writes controlTag (0x1c) = '    ', enabled/viewEnabled = 1, nextHandler = the argument.
  void IEventHandler(TEventHandler* nextHandler);

  // Slot 0x00 — MFC RTTI accessor (this is CObject::GetRuntimeClass; the whole "T"
  // hierarchy is MFC DECLARE_DYNAMIC rooted at CObject). Every descendant overrides it
  // to return its own CRuntimeClass descriptor. See CRuntimeClass chain
  // CObject<-TObject<-TEventHandler<-TView<-TControl<-...
  DECLARE_DYNCREATE(TEventHandler)
  virtual ~TEventHandler() override;       // 0x01
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
  virtual char DoIdle(int action);               // 0x13 0x48a480 (MacApp DoIdle)

  // MacApp Handle*/Do* pair, mirroring HandleEvent -> DoEvent at 0x48a2e0: the
  // non-virtual entry point simply dispatches through this handler's own virtual.
  void HandleMenuCommand(int command);              // 0x0048a340 -> slot 0x11
  void HandleKeyEvent(TToolboxEvent* event);        // 0x0048a360 -> slot 0x12
  virtual int GetIdleFreq();                        // 0x14 0x415d50
  virtual void SetIdleFreq(int frequency);          // 0x15 0x415d70
  virtual TWindow* GetWindow();                     // 0x16
  virtual char WantsToBeTarget();                   // 0x17 0x48a530
  virtual char WillingToResignTarget();             // 0x18 0x48a550
  virtual void ResignedTarget();                    // 0x19 0x48a690
  virtual void TargetValidationFailed(int reason);  // 0x1a 0x48a6b0
  virtual void TargetValidationSucceeded();         // 0x1b 0x48a650
  virtual void BecameWindowTarget();                // 0x1c 0x48a6d0
  virtual void ResignedWindowTarget();              // 0x1d 0x48a670
  virtual void BecameTarget();                      // 0x1e 0x48a6f0
  virtual char BecomeTarget();                      // 0x1f 0x48a570
  virtual char ResignTarget();                      // 0x20 0x48a5e0
  virtual void SelectOwner(unsigned char select);   // 0x21 0x48a710
  virtual char IsTarget();                          // 0x22 0x48a500
  virtual void RemoveBehavior(TBehavior* behavior); // 0x23 0x48a4a0
  virtual void AddBehavior(TBehavior* behavior);    // 0x24 0x48a4d0
};
ASSERT_SIZE(TEventHandler, 0x20);

// Builds a TEvent (commandNumber = dispatchMessage = commandId, sourceHandler = control,
// targetHandler = owner) and forwards it to owner->DispatchQueuedUiCommandAndRelease.
// 0x5d4b30.
void QueueDeferredUiEventPacket(TView* owner, int commandId, TView* control);
