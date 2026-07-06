#pragma once

#include "game/TControl.h"
#include "game/TView.h"

// Provisional interfaces for the runtime-resolved turn-event dialog and its 'GOLD'
// child control. These are never constructed here — they only give names to the
// vtable slots dispatched on the concrete (not-yet-recovered) dialog/control classes
// returned by TAssetMgr::ResolveTurnEventDialogNodeByMessageContext and
// TView::ResolveControlByTag(0x444c4f47 == 'GOLD'). Both TViewMgr.cpp and
// TMacViewMgr.cpp resolve the identical runtime objects, so a single shared
// definition prevents the two copies from drifting (bd imperialism-decomp-hpd.7).
//
// The turn-event slots 0x68..0x6e and the GOLD control's 0x71/0x72 are consistent
// across every call site. Slots that correspond to real, already-recovered TView
// methods (ResolveControlByTag 0x25, CallVoidSlotA0 0x28, CaptureLayoutF0 0x3c, Free
// 0x07) are NOT redeclared here — callers invoke those real inherited methods
// directly. The remaining Slot* names below are still provisional pending recovery of
// the concrete dialog/control classes.
namespace turn_event_dialog {

// The city order object queried by the city-order dialog population path.
struct CityOrderSource {
  virtual char QuerySellModeFlag1D8() = 0;
  virtual short QuerySellQuantity1D4() = 0;
};

struct TurnEventDialogNode : public TView {
  virtual void ShowTurnEventDialog(int flag); // slot 0x68 byte 0x1a0
  virtual void node69();                      // slot 0x69
  virtual void node6a();                      // slot 0x6a
  // Returns a status/tag value that some callers forward to the 'GOLD' child (see
  // HandleTurnEventDialogFactorySlotB8); most callers ignore it (codegen-neutral).
  virtual int RefreshTurnEventDialog();        // slot 0x6b byte 0x1ac
  virtual void node6c();                       // slot 0x6c
  virtual void node6d();                       // slot 0x6d
  virtual void* QueryTurnEventContentObject(); // slot 0x6e byte 0x1b8
  virtual void DispatchSlot9C();
  virtual void SetDialogModeSlotF0(int mode);
  virtual void InvokeSlotF0WithPair(short a, short b);
  virtual void SetDialogActiveFlag(int flag);
  virtual void InvokeSlotA0();
  virtual void InvokeSlot1C();
};

struct GoldDialogControl : public TControl {
  virtual void gold71();                                    // slot 0x71 byte 0x1c4
  virtual void SetGoldControlStateByResource(int a, int b); // slot 0x72 byte 0x1c8
  virtual void InvokeSlot1CC(int a, int b, int c);
  virtual void InvokeSlot1D0FourParam(int a, int b, int c, int slot);
  virtual void InvokeSlot1D0OneParam(void* content);
};

// The 'GOLD' child of the factory dialogs opened by HandleTurnEventDialogFactorySlot78
// dispatches a zero-argument commit through byte 0x1a0 — a different subclass family
// than TurnEventDialogNode (whose 0x1a0 is ShowTurnEventDialog(int)) and than TControl
// (whose slot 0x68 takes four arguments).
struct GoldCommitControl : public TView {
  virtual void CommitGoldDialogContent(); // slot 0x68 byte 0x1a0
  // Padding to reach the later 'GOLD' control slots dispatched by the turn-event
  // handlers. Only the byte-annotated slots below are actually called; the rest keep
  // the vtable indices aligned on the (not-yet-recovered) concrete control class.
  virtual void goldSlot69();
  virtual void goldSlot6a();
  virtual void goldSlot6b();
  virtual void goldSlot6c();
  virtual void goldSlot6d();
  virtual void goldSlot6e();
  virtual void goldSlot6f();
  virtual void goldSlot70();
  virtual void goldSlot71();
  virtual void goldSlot72();
  // dialog 0x2405 'GOLD' trade-summary child (HandleTurnEventDialogFactorySlotB8).
  virtual void ApplyGoldTradeSummaryValues(int a, int b, int c);     // slot 0x73 byte 0x1cc
  virtual void ApplyGoldTradeDialogRefreshResult(int refreshResult); // slot 0x74 byte 0x1d0
  virtual void goldSlot75();
  virtual void goldSlot76();
  virtual void goldSlot77();
  virtual void goldSlot78();
  virtual void ConfigureGoldValueCells(int cellWidth, int cellHeight); // slot 0x79 byte 0x1e4
};

} // namespace turn_event_dialog
