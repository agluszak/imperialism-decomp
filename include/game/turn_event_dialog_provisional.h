#pragma once

#include "game/TControl.h"
#include "game/TView.h"

class TCivUnit;
class TViewMgr;

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
// methods (ResolveControlByTag 0x25, Close 0x28, CaptureLayoutF0 0x3c, Free
// 0x07) are NOT redeclared here — callers invoke those real inherited methods
// directly. The remaining Slot* names below are still provisional pending recovery of
// the concrete dialog/control classes.
namespace turn_event_dialog {

// The city order object queried by the city-order dialog population path. A view over
// some other real class's vtable (reinterpret_cast'd in TMacViewMgr.cpp); adding a
// destructor slot here would shift these two slots off the real object's layout.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
struct CityOrderSource {
  virtual char QuerySellModeFlag1D8() = 0;
  virtual short QuerySellQuantity1D4() = 0;
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

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
  virtual void gold71(); // slot 0x71 byte 0x1c4
  // The resource parameter is short-typed: 0x5d5f19..0x5d5f34 passes
  // GetActiveNationId()+0x251c with no movsx (garbage upper word), which only
  // compiles when the receiving parameter is a short.
  virtual void SetGoldControlStateByResource(short resourceId, int b); // slot 0x72 byte 0x1c8
  virtual void InvokeSlot1CC(int a, int b, int c);
  virtual void InvokeSlot1D0FourParam(int a, int b, int c, int slot);
  virtual void InvokeSlot1D0OneParam(void* content);
};

// A distinct 'GOLD' concrete class from GoldDialogControl: dialog 0x546's 'GOLD' child
// (HandleTurnEventDialogFactorySlotD8, 0x5dcf20) dispatches byte 0x1cc with a single
// TViewMgr* argument, whereas GoldDialogControl's own 0x1cc override (verified at
// TMacViewMgr::OpenConstructionWindow, dialog 0x2404) takes three arguments -- proof
// these are two different runtime classes sharing the 'GOLD' tag and this byte offset,
// not one type (see the Type-modeling guardrail's "never borrow a type" rule).
struct GoldFactoryPanel : public TControl {
  virtual void goldPanel71();                                    // slot 0x71 byte 0x1c4
  virtual void goldPanelSetControlStateByResource(int a, int b); // slot 0x72 byte 0x1c8
  virtual void NotifyDialogOwner(TViewMgr* viewMgr);             // slot 0x73 byte 0x1cc
};

// Concrete siblings used by TViewMgr's modal-dispatch slots. They share the
// TView/TControl prefix but interpret later slots differently, so keeping them
// separate avoids assigning one caller's signature to every 'GOLD' control.
struct MainActionControl : public TControl {
  virtual void mainAction71();
  virtual void mainAction72();
  virtual void InvokeMainAction(int sourceNation, int arg1, int arg2, int arg3,
                                int targetNation); // slot 0x73 byte 0x1cc
};

struct GoldSinglePayloadControl : public TControl {
  virtual void goldPayload71();
  virtual void goldPayload72();
  virtual void ApplyPayload(void* payload); // slot 0x73 byte 0x1cc
};

struct ThreeFlagDialogNode : public TView {
  virtual void ShowTurnEventDialog(int flag); // slot 0x68 byte 0x1a0
  virtual void dialog69();
  virtual void dialog6a();
  virtual int RefreshTurnEventDialog(); // slot 0x6b byte 0x1ac
  virtual void dialog6c();
  virtual void dialog6d();
  virtual void dialog6e();
  virtual void dialog6f();
  virtual void dialog70();
  virtual void ConfigureDialogFlags(int a, int b, int c); // slot 0x71 byte 0x1c4
};

struct GoldDialogValueControl : public TView {
  virtual void ApplyDialogValue(void* value); // slot 0x68 byte 0x1a0
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
  // Notified with TViewMgr::currentTurnEventCode before a dialog-factory slot resolves
  // its own factory dialog node (HandleTurnEventDialogFactorySlotD8/E8, 0x5dcf20/0x5dd770).
  virtual void NotifyGoldControlOfTurnEventCode(short eventCode); // slot 0x76 byte 0x1d8
  virtual void goldSlot77();
  virtual void goldSlot78();
  virtual void ConfigureGoldValueCells(int cellWidth, int cellHeight); // slot 0x79 byte 0x1e4
};

// The per-order-slot city-production row container passed to
// TMacViewMgr::SyncSellTaggedChildControlWithNationState (0x50bc50) — the row that owns
// the 'Sell'-tagged GoldCommitControl-family child. Concrete class not yet recovered.
// Dispatches four zero-argument notify hooks through bytes 0x1e0/0x1e4/0x1e8/0x1ec — the
// SAME byte offsets GoldCommitControl uses for its 2-arg ApplyGoldTradeDialogRefreshResult
// (0x1d0)/ConfigureGoldValueCells (0x1e4), but with a different (0-arg) signature, so this
// is a sibling class, not GoldCommitControl itself (same pattern as the TControl-vs-
// GoldCommitControl slot-0x68 divergence noted above).
struct TSellOrderRowControl : public TView {
  virtual void rowSlot68();
  virtual void rowSlot69();
  virtual void rowSlot6a();
  virtual void rowSlot6b();
  virtual void rowSlot6c();
  virtual void rowSlot6d();
  virtual void rowSlot6e();
  virtual void rowSlot6f();
  virtual void rowSlot70();
  virtual void rowSlot71();
  virtual void rowSlot72();
  virtual void rowSlot73();
  virtual void rowSlot74();
  virtual void rowSlot75();
  virtual void rowSlot76();
  virtual void rowSlot77();
  virtual void NotifySellValueValid();        // slot 0x78 byte 0x1e0 (sellCount >= 0 path)
  virtual void NotifySellValueUnavailable();  // slot 0x79 byte 0x1e4 (sellCount < 0 path)
  virtual void NotifySellValueActive();       // slot 0x7a byte 0x1e8 (sellCount > 0 path)
  virtual void NotifySellCapacityAvailable(); // slot 0x7b byte 0x1ec
};

} // namespace turn_event_dialog
