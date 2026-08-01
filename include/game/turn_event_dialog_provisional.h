#pragma once

#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TView.h"

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
// methods (ResolveControlByTag 0x25, Close 0x28, Locate 0x3c, Free
// 0x07) are NOT redeclared here — callers invoke those real inherited methods
// directly. The remaining Slot* names below are still provisional pending recovery of
// the concrete dialog/control classes.
namespace turn_event_dialog {

// Resolved against g_pDisplayMgr->activeDialog's 'main' child -- i.e. whatever dialog
// happens to be open -- so there is no single concrete class to look up. Kept separate
// from the 'DLOG' interfaces so one caller's signature is never assigned to another's
// control (the "never borrow a type" guardrail).
struct MainActionControl : public TControl {
  virtual void mainAction71();
  virtual void mainAction72();
  virtual void InvokeMainAction(int sourceNation, int arg1, int arg2, int arg3,
                                int targetNation); // slot 0x73 byte 0x1cc
};

// The unresolved 'DLOG' child used by the tactical-map selection dialog. Slot 0x68
// consumes an opaque selection object; keep the argument opaque until that concrete
// resource class is recovered rather than borrowing another dialog's payload type.
struct TDialogValueControl : public TView {
  virtual void StuffValues(void* value); // slot 0x68 byte 0x1a0
};

} // namespace turn_event_dialog
