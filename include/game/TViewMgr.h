#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TToolBarClusterVtbl;
class TView;
class TEventHandler;
class TControl;
class TCursorControlPanel;
class TDiplomacyMapView;
class TMovieView;
class TTaskForce;

// VTABLE: IMPERIALISM 0x0066f120
class TViewMgr : public TObject {
public:
  // Base Windows cursor resource ID for cursorTable's indexing scheme (see below).
  enum { kCursorResourceIdBase = 1000 };

  // === BEGIN GENERATED DECLS (TViewMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TViewMgr)
  virtual ~TViewMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5d5250
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5d5200
  virtual void Free() override;                    // slot 0x07 0x5d51e0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void LoadTurnEventCursorTable();                                     // slot 0x0a 0x5d5100
  virtual void HandleTurnEventVtableSlot2CInitializeHotKeyDialog();            // slot 0x0b 0x5dcaa0
  virtual void UpdatePaletteIndexFromTurnEventCode(int eventCode);             // slot 0x0c 0x5d5780
  virtual void ApplyTurnEventPaletteColorByEventCode(int eventCode);           // slot 0x0d 0x5d5750
  virtual int ClassifyTurnStateForOverlayMode();                               // slot 0x0e 0x5d5960
  virtual void BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg); // slot 0x0f 0x5d6480
  virtual void HandleTurnEventVtableSlot40RefreshGoldDialog();                 // slot 0x10 0x5d57b0
  virtual void ComputeTurnEventDialogPlacementByCode(TView* dialogView,
                                                     POINT* outPlacement); // slot 0x11 0x5d69b0
  virtual void RefreshMainViewNationIndicatorForCurrentTurnEvent();        // slot 0x12 0x5d6b70
  // === END GENERATED DECLS (TViewMgr) ===

  // Extended UI-runtime virtuals (same object as g_pUiRuntimeContext @ 0x006A21BC).
  virtual void DispatchTurnEventSlot4C(short eventCode, int payload); // 0x4c
  virtual void UiRuntimeSlot50(int payload);                          // 0x50
  virtual short GetPendingTurnOverlayCode();                          // 0x54
  virtual void UiRuntimeSlot58();                                     // 0x58
  virtual void UiRuntimeSlot5C();                                     // 0x5c
  virtual void UiRuntimeSlot60();                                     // 0x60
  virtual void UiRuntimeSlot64();                                     // 0x64

  // UI runtime helper functions
  virtual void AddPendingTurnOverlayCode(int modeValue); // 0x68
  virtual void UiRuntimeSlot6C();                        // 0x6c
  // Resolve the factory dialog for eventCode, commit its 'GOLD' child, then push the
  // slot-0x9c refresh down the dialog's linked children (0x5d6cd0).
  virtual void HandleTurnEventDialogFactorySlot70(int eventCode); // 0x70 0x5d6cd0
  // Slots 0x74/0x78/0x7C/0x80 share the same body: resolve the factory dialog for
  // eventCode, commit its 'GOLD' child, then show/refresh/free the dialog node.
  virtual void HandleTurnEventDialogFactorySlot74(int eventCode); // 0x74 0x5d6d70
  virtual void HandleTurnEventDialogFactorySlot78(int eventCode); // 0x78 0x5d6e50
  virtual void HandleTurnEventDialogFactorySlot7C(int eventCode); // 0x7c 0x5d6f10
  virtual void HandleTurnEventDialogFactorySlot80(int eventCode); // 0x80 0x5d6fd0
  virtual void UiRuntimeSlot84();                                 // 0x84
  virtual void UiRuntimeSlot88();                                 // 0x88
  virtual void UiRuntimeSlot8C(int arg);                          // 0x8c
  virtual char RequestDiplomacyDecisionSlot90(int sourceNation, int targetNation,
                                              int proposalCode); // 0x90
  virtual char RequestDecisionSlot94(int sourceNation, int arg1, int arg2,
                                     int promptCode); // 0x94
  virtual void DispatchDecisionSlot98(int sourceNation, int arg2, int arg3,
                                      int targetNation);                // 0x98
  virtual void UiRuntimeSlot9C();                                       // 0x9c
  virtual void UiRuntimeSlotA0();                                       // 0xa0
  virtual void UiRuntimeSlotA4(int payload, TEventHandler* waitTarget); // 0xa4
  virtual void UiRuntimeSlotA8();                                       // 0xa8
  // Forwards to g_pStrategicMapViewSystem's own vtable slot 0x5c/0x60/0x68/0x6c/
  // 0x70/0x74 (TMacViewMgr) -- verified via disassembly (0057db14-style pattern:
  // `mov ecx,[g_pStrategicMapViewSystem]; mov eax,[ecx]; jmp [eax+0xNN]`, no
  // wrapping logic). Real orig names embed the target slot's byte offset. bd
  // imperialism-decomp-kdm.
  virtual void InvokeStrategicMapViewMethod5C();             // 0xac 0x5d7f70
  virtual void InvokeStrategicMapViewMethod60(short param1); // 0xb0 0x5d7f90
  virtual void UiRuntimeSlotB4();                            // 0xb4
  // Opens factory dialog 0x2405, seeds its 'GOLD' trade-summary child with the three
  // caller args, places/refreshes it, then forwards the refresh result to the child
  // (0x5dc430).
  virtual void HandleTurnEventDialogFactorySlotB8(int a, int b, int c); // 0xb8 0x5dc430
  virtual void UiRuntimeSlotBC();                                       // 0xbc
  virtual undefined InvokeStrategicMapViewMethod68();                   // 0xc0 0x5dc180
  virtual undefined InvokeStrategicMapViewMethod70();                   // 0xc4 0x5dc1c0
  virtual undefined InvokeStrategicMapViewMethod74();                   // 0xc8 0x5dc1a0
  virtual void InvokeStrategicMapViewMethod6C();                        // 0xcc 0x5dc160
  virtual void UiRuntimeSlotD0();                                       // 0xd0
  virtual void UiRuntimeSlotD4(int arg);                                // 0xd4
  virtual void UiRuntimeSlotD8();                                       // 0xd8
  virtual int ShowConstructionOptionsDialog();                          // 0xdc
  virtual void UiRuntimeSlotE0();                                       // 0xe0
  // Opens factory dialog 0x1c52, places it, and sets the 'GOLD'->'name' text from a
  // localized string code (0x5dd220).
  virtual void HandleTurnEventDialogFactorySlotE4(int stringCode); // 0xe4
  virtual void UiRuntimeSlotE8();                                  // 0xe8
  // Refreshes the 0xdac factory dialog's 'page' roster for a tile-selection map click
  // (0x5dd900); reached from TArmyToolbar's map-tile-selection handler.
  virtual void HandleTurnEventDialogFactorySlotEC(int mapSelection); // 0xec
  // Real arity confirmed from TToolBarCluster::TryHandleMapContextAction's case-10 call
  // site: ecx=g_pUiRuntimeContext, one pushed arg = GetActiveMapOrderEntry()'s result
  // (a TTaskForce*). TODO: real slot body not yet ported.
  virtual void UiRuntimeSlotF0(TTaskForce* activeMapOrderEntry); // 0xf0
  virtual void HandleTurnEventDialogFactorySlotF4();             // 0xf4
  virtual void UiRuntimeSlotF8();                                // 0xf8
  virtual void NoOpTurnEventStateVtableSlotFC(); // 0xfc 0x5dbd10 -- real body is a bare `ret`
  // Turn-event 0x5DE: re-assert + refresh the 'main' view panel (sibling of the 0x5DF
  // handler; the original brackets the body with a scoped empty CString). 0x5dbd30.
  virtual void HandleTurnEvent5DE_RefreshMainView(); // 0x100 0x5dbd30
  // Turn-event 0x5DF path (see DispatchTurnEventSlot4C): re-asserts and refreshes
  // the main view's 'main' panel (0x5dbdd0).
  virtual void HandleTurnEvent5DF_RefreshMainView(); // 0x104
  virtual void UiRuntimeSlot108();                   // 0x108
  // Resolves the active dialog's 'GOLD' control and configures its value-cell grid
  // (0x14 x 0x14) via the control's slot-0x79 virtual (0x5dc3f0).
  virtual void
  HandleTurnEventTable66F220_Slot0C_InvokeGoldViewSlots0C_1E4_14x14();        // 0x10c 0x5dc3f0
  virtual void HandleTurnEventF3D_PopulateRecentTurnMessages(int nationSlot); // 0x110

  void ApplyLegendSplitSlot34(int split) {
    ApplyTurnEventPaletteColorByEventCode(split);
  }
  void QueueTurnStatusPromptSlot3C(int promptIndex, int payload) {
    BuildAndShowTurnOverlayByMode(promptIndex, payload);
  }
  void RefreshViewSlot48() {
    RefreshMainViewNationIndicatorForCurrentTurnEvent();
  }

  int MapTurnEventCodeToPaletteIndex(int eventCode);

  // 0x5d7090 / 0x5d7100 — turn-event 0x7D8: dispatch the event via slot 0x4C, then resolve the
  // active dialog's 'main' control (a TDiplomacyMapView) and forward the tab-switch to its child.
  // The 0x7100 variant early-outs while the turn-cooldown counter is active and finishes through
  // the direct InvalidateAndRunChildWaitSheet path instead of the slot-0x79 virtual.
  void DispatchTurnEvent7D8AndUpdateMainViewSelection(void* a1, void* a2, void* a3);
  char DispatchTurnEvent7D8IfTurnFlowIdle(void* a1, void* a2, void* a3, void* a4);

  // 0x5ddd20 — opens the civilian ledger (TSuperCivRoster) inside factory dialog
  // 0xdac, runs it modally via the show/refresh chain, then applies the selected
  // civilian as the active map selection.
  void ShowCivilianLedgerDialogAndSelectUnit();

  // 0x5dea60 — allocates a TModalMessageCommand carrying `message`/`payload`, seeds
  // it with dispatch code 'Hey!' targeting the global UI root controller, and posts
  // it there. `this` is unused by the original body.
  void CreateModalMessageCommandAndQueue(CString* message, int payload);
  // 0x005d5a70 (ret 0x8) — dispatches `message` via A13A0 with overlayMode from
  // ClassifyTurnStateForOverlayMode (slot 0x38).
  void RunControlStringProviderAndDispatchLocalizedMessage(CString message,
                                                           CString* messageStoreRef);
  // 0x005d5b00 (ret 0x10) — takes the message BY VALUE (copy-constructed into the
  // arg slot by every caller, destroyed by the callee) and forwards it plus an
  // empty format CString to DispatchLocalizedUiMessageWithTemplate(3, ...).
  // messageStoreRef is a per-subsystem CString global (may be null: TNetMgr).
  undefined1 DispatchLocalizedUiMessageWithTemplateA13A0(CString message, CString* messageStoreRef,
                                                         int overlayMode, int arg4);
  // 0x5de990 — load string (group, index) and pose it through the localized-message
  // dispatch; returns the prompt result byte.
  char ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex, int overlayMode,
                                            int arg4);
  // 0x5deb40 — pose the confirm prompt matching `actionTag` ('magc'/'gwen'/'quit'/
  // 'load'; group 0x2737 index by game-flow mode) and, when accepted during session
  // teardown, dispatch the 'abdi' game-state event. Returns the accepted byte.
  char DispatchGameStateEventIfLocalizedPromptAccepted(int actionTag);
  // 0x005d5c40 (ret 0x18) — the real message-window dispatch; body still TODO.
  undefined1 DispatchLocalizedUiMessageWithTemplate(int templateKind, CString formatText,
                                                    CString message, CString* messageStoreRef,
                                                    int overlayMode, int arg4);

  // 0x5de4f0. Shows the Civilian Report confirmation dialog (resource 0xbc4) for
  // pCivilianOrderEntry and returns true iff the player picked "confirm" ('okay').
  // TODO(port): real body creates the dialog via g_pUiViewManager and formats its message
  // text through a 'DLOG'-tagged control -- not yet ported; stubbed to the conservative
  // "confirm, no changes" default so callers don't act on unverified dialog state.
  bool ShowCivilianReportDialogAndReturnConfirm(class TCivUnit* pCivilianOrderEntry);

  // Object layout recovered from ctor 0x5d5060 / ReadFrom 0x5d5200 /
  // LoadTurnEventCursorTable 0x5d5100. Field names past the event code are
  // provisional. Total size 0xfc, base TObject = 0x4.
  short currentTurnEventCode;   // +0x04 (turn-event dispatch code)
  short pad06;                  // +0x06
  unsigned int turnStateSeedLo; // +0x08 (seeded from g_dat_006a5b58)
  unsigned int turnStateSeedHi; // +0x0c (seeded from g_dat_006a5b5c)
  unsigned char field10;        // +0x10
  unsigned char pad11[3];       // +0x11
  // +0x14 .. 0xeb (54 turn-event cursor handles). Indexed as
  // cursorTable[resourceCursorId - kCursorResourceIdBase] -- confirmed against
  // TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback's ground-truth
  // `[EAX + EDX*4 + 0xfffff074]` (0xfffff074 == -0xf8c == 0x14 - kCursorResourceIdBase*4).
  void* cursorTable[0x36];
  short fieldEc;                           // +0xec
  short padEe;                             // +0xee
  class TMapUberPicture* mapUberPictureF0; // +0xf0
  TMovieView* activeMovieViewF4;           // +0xf4
  short fieldF8;                           // +0xf8
  short padFa;                             // +0xfa

  TViewMgr();

  // Screen-exit backbone: stash the followup turn state in fieldF8; on state 0,
  // re-apply volume preferences and post the followup turn-event code (0x5dc menu /
  // 0x7e0 / 0x5eb) via g_pGlobalUiRootController->PostTurnEventCodeMessage2420.
  void HandleTurnStateExitAndPostFollowupEventCode(short followupState); // 0x5db620
};

ASSERT_SIZE(TViewMgr, 0xfc);
