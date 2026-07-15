#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TObject.h"

class CArchive;
class TView;
class TControl;
class TEvent;

//
// The real shared base of TView and TApplication (TApplication). Both
// inherit this 37-slot interface (slots 0x00-0x24) and the fields through +0x1c; they
// diverge at +0x20 (TView::ownerContext vs TApplication::activeView) and
// each introduces its own virtuals at slot 0x25+. Proven by vtable comparison: TView
// (0x649858) and TApplication (0x648bd8) share the same body addresses for
// most of slots 0x02-0x24, overriding only a handful. Methods kept with their TView-era
// vmethod_* / semantic names so existing by-name callers/overrides keep resolving.
// VTABLE: IMPERIALISM 0x006497a0
class TEventHandler : public TObject {
public:
  int field04;
  union {
    int field08;
    TEventHandler* resourceOwnerBackLink;
  };
  union {
    int field0c;
    TEventHandler* linkedChildHandler;
  };
  int field10;
  int field14;
  TEventHandler* linkedResourceOwner;
  int controlTag; // 0x1c

  TEventHandler();

  void CreateTEventHandlerInstance();

  // 0x48a410 — MacApp TEventHandler::HandleIdle(IdlePhase); throttled idle dispatch
  // using field10 (idle frequency, 0x7fffffff = never) / field14 (last-idle stamp).
  void HandleIdle(int idlePhase);

  // Standalone binary helper @ 0x48a100 (also reached via ILT 0x403049).
  void InitializeUiResourceEntryBaseHeaderDefaults();

  // __thiscall packet/event-header field initializer (0x48a180, also reached via ILT 0x40174e).
  // Writes controlTag (0x1c) = 0x20202020, field04/field08 = 1, field0c = packetTag.
  void InitializePacketHeaderFields_Tag20202020(int packetTag);

  // Slot 0x00 — MFC RTTI accessor (this is CObject::GetRuntimeClass; the whole "T"
  // hierarchy is MFC DECLARE_DYNAMIC rooted at CObject). Every descendant overrides it
  // to return its own CRuntimeClass descriptor. See CRuntimeClass chain
  // CObject<-TObject<-TEventHandler<-TView<-TControl<-...
  DECLARE_DYNCREATE(TEventHandler)
  virtual ~TEventHandler() override;       // 0x01
  void Free() override;                    // 0x07 0x48a1b0
  TObject* ShallowClone() override;        // 0x08 0x48a7c0 base; TView override 0x48bfd0
  virtual char GetBoolSlot28();            // 0x0a 0x48a240 GetCityDialogFlagByte4
  virtual void SetControlValue(int value); // 0x0b 0x48a260 SetCityDialogFlagByte4
  virtual TEventHandler* QueryStepValue(); // 0x0c 0x48a2c0 GetCityDialogValueDwordC
  virtual void DispatchQueuedUiCommandAndRelease(void* payload); // 0x0d 0x48a3b0
  virtual void DispatchUiSelectionToHandler(void* payload);      // 0x0e 0x48a3f0
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event); // 0x0f 0x48a280
  virtual void DispatchEvent(int commandId, TEventHandler* sourceHandler,
                             TEvent* event);          // 0x10 0x48a2e0 DoEvent
  virtual void vmethod_0017(int param);               // 0x11 0x48a310
  virtual void ForwardParam(int param);               // 0x12 0x48a380
  virtual char DoIdle(int action);                    // 0x13 0x48a480 (MacApp DoIdle)
  virtual int GetCityDialogValueDword10();            // 0x14 0x415d50 field10
  virtual void SetCityDialogValueDword10(int value);  // 0x15 0x415d70
  virtual class TView* OwnerPanel();                  // 0x16
  virtual char vmethod_0023();                        // 0x17 0x48a530
  virtual char GetDeactivateVetoCode();               // 0x18 0x48a550
  virtual void OnDeactivated();                       // 0x19 0x48a690
  virtual void OnDeactivateVetoed(int gate);          // 0x1a 0x48a6b0
  virtual void HandleCityProductionNoOp();            // 0x1b 0x48a650
  virtual void DispatchUiCommand19ToParent();         // 0x1c 0x48a6d0
  virtual void DispatchCityProductionAction1A();      // 0x1d 0x48a670
  virtual bool ContinueModal();                       // 0x1e 0x48a6f0
  virtual char ActivateCityProductionViewIfAllowed(); // 0x1f 0x48a570
  virtual char TryDeactivateActiveView();             // 0x20 0x48a5e0
  virtual void vmethod_0081(int param);               // 0x21 0x48a710
  virtual char IsActiveView();                        // 0x22 0x48a500
  virtual void DetachUiResourceOwnerIfMatches(TEventHandler* owner); // 0x23 0x48a4a0
  virtual void SetUiResourceOwner(TEventHandler* owner);             // 0x24 0x48a4d0
};
