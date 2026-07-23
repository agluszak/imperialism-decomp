#pragma once

#include "game/TControl.h"
#include "game/TPicture.h"
#include "game/TView.h"

class TCivUnit;
class TViewMgr;

// Provisional interfaces for the runtime-resolved 'DLOG'-tagged dialog children that
// are still without a concrete class. These are never constructed here -- they only
// name the vtable slots dispatched on the runtime object.
//
// The dialog *node* is no longer one of them: everything
// TAssetMgr::ResolveTurnEventDialogNodeByMessageContext returns is a TWindow, and its
// three "provisional" slots are TWindow's own SetModality (0x68), PoseModally (0x6b)
// and GetDialogBehavior (0x6e); Center (0x71) is the three-flag call. Where the child
// control's dialog id is fixed, the Mac resource oracle
// (vendor/macos_codewarrior/evidence/resources/widgets.csv) names it outright -- that
// is how TCivReport, TArmyInfoView, TCombatReportView and TPlaceCityDialog replaced
// their facades. What is left below is only the receivers resolved against whatever
// dialog happens to be open, which need a recovered shared base rather than a
// per-view lookup.
//
// The turn-event slots 0x68..0x6e and the GOLD control's 0x71/0x72 are consistent
// across every call site. Slots that correspond to real, already-recovered TView
// methods (ResolveControlByTag 0x25, Close 0x28, CaptureLayoutF0 0x3c, Free
// 0x07) are NOT redeclared here — callers invoke those real inherited methods
// directly. The remaining Slot* names below are still provisional pending recovery of
// the concrete dialog/control classes.
namespace turn_event_dialog {

// The status-icon control TViewMgr hands to TMacViewMgr::ApplySellOrderRowToNationState.
// Its two queried slots sit at bytes 0x1d4/0x1d8, past TPicture's own 0x72, so it is a
// TPicture subclass whose concrete identity is not recovered yet -- the two slots between
// are the only padding left here, and deriving from TPicture is what lets the call site
// use a plain downcast instead of the old reinterpret_cast bridge.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
struct CityOrderSource : public TPicture {
  virtual void cityOrderSlot73();
  virtual void cityOrderSlot74();
  virtual short QuerySellQuantity1D4(); // slot 0x75 byte 0x1d4
  virtual char QuerySellModeFlag1D8();  // slot 0x76 byte 0x1d8
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

// Slots 0x71/0x72 are NOT declared here: they are TPicture::ResetPictureResourceEntry
// and TPicture::SetPictureResourceIdAndRefresh, and every caller now uses TPicture
// directly. What remains are the per-dialog overrides at 0x1cc/0x1d0 whose concrete
// classes still need the Mac resource oracle applied per dialog id.
struct GoldDialogControl : public TPicture {
  virtual void InvokeSlot1CC(int a, int b, int c);
  virtual void InvokeSlot1D0FourParam(int a, int b, int c, int slot);
  virtual void InvokeSlot1D0OneParam(void* content);
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

// The 'DLOG' child of event 0xf0a's dialog. Its slot 0x68 is the class's first new
// virtual (TView ends at 0x67) and takes one argument, exactly like TEngineerDialog's
// BuildCityViewProductionControls at the same index -- but the Mac resource oracle has
// no view for 0xf0a, so the concrete class is genuinely unknown here.
struct TDialogValueControl : public TView {
  virtual void StuffValues(void* value); // slot 0x68 byte 0x1a0
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
  virtual void goldSlot73();
  virtual void goldSlot74();
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
