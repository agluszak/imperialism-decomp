#pragma once

#include "compat.h"
#include "game/TEventHandler.h"
#include "game/mfc.h"

class TStream;
struct NetMessage;

// Multiplayer session / game-flow manager (g_pGameFlowState). Inherits the shared
// TEventHandler control surface used by UI roots; vtable @ 0x0065c030.
// VTABLE: IMPERIALISM 0x0065c030
class TMultiplayerMgr : public TEventHandler {
public:
  DECLARE_DYNCREATE(TMultiplayerMgr)
  enum { kNationSlotCount = 7 };

  int nationStatusControlSlots[8];        // +0x20
  int field40;                            // +0x40
  int diplomacyQueueContext;              // +0x44 — child handler for queue routing
  int nationSessionIds[kNationSlotCount]; // +0x48
  int queueSyncDword;                     // +0x64
  char processPrimaryEventQueue;          // +0x68
  char processSecondaryEventQueue;        // +0x69
  unsigned char pad6a[2];
  int primaryTurnEventQueueHead;                    // +0x6c
  int secondaryTurnEventQueueHead;                  // +0x70
  CString gameNameString;                           // +0x74
  CString defaultNationTextSlots[kNationSlotCount]; // +0x78
  CString nationDisplayNameSlots[kNationSlotCount]; // +0x94
  CString playerNameString;                         // +0xb0
  CString playerNameMirror;                         // +0xb4
  CString fieldb8;                                  // +0xb8
  int nationStatusTags[kNationSlotCount];           // +0xbc — four-cc tags ('suna', 'lwoa', …)
  int sessionPhaseTag;                              // +0xd8 — four-cc phase tag ('adam', 'init', …)
  unsigned char activeNationTagIndex;               // +0xdc
  unsigned char padDd[3];
  int scenarioSelectionTag;       // +0xe0 — four-cc from the code-0xe session-init packet
                                  // ('load', 'rand', 'scn0'..'szz9')
  unsigned char sessionReadyFlag; // +0xe4
  unsigned char padE5[3];
  int pendingNationBitmask;   // +0xe8 — one bit per nation slot; the turn-state machine
                              // loads it whole from the code-1 sync packet and clears the
                              // sender's bit on code-0x32 acknowledgements
  int activeNationSlotIndex;  // +0xec
  int pendingNationSlotIndex; // +0xf0
  unsigned char fieldF4;      // +0xf4
  unsigned char padF5[3];

  virtual ~TMultiplayerMgr() override;                              // slot 0x01 0x5427e0
  virtual void WriteTo(TStream* stream) override;                   // slot 0x05 0x542ff0
  virtual void ReadFrom(TStream* stream) override;                  // slot 0x06 0x542be0
  virtual void Free() override;                                     // slot 0x07 0x542b10
  virtual char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x544e30
  // Ground truth (0x542923): the argument is stored raw into the inherited int
  // TEventHandler::field10; every observed caller (0x5818ee, TAmbitApplication init)
  // pushes literal 0 — not a by-value CString as Ghidra guessed.
  virtual undefined
  InitializeMultiplayerManagerForSessionContext(int sessionContext); // slot 0x25 0x542900

  TMultiplayerMgr();

  // Turn-event emitters (non-virtual __thiscall; `this` unused in the bodies). Every
  // original callsite loads ECX from g_pGameFlowState (0x6a43c8) and the bodies end in
  // callee-cleanup `ret n`, so these are real TMultiplayerMgr methods, not free
  // functions. They build a stack packet and hand it to TNetMgr::Send via the
  // g_pNetMgr006a6014 global.
  void EmitTurnEvent3Mode18WithActiveNation();                         // 0x5446a0
  void CreateAndSendTurnEvent12_TwoShorts(short shortA, short shortB); // 0x5494b0
  void CreateAndSendTurnEvent13_NationAndNineDwords(int nationSlot,
                                                    int* payloadDwords);             // 0x549540
  void CreateAndSendTurnEvent22_ByteAndShort(unsigned char byteVal, short shortVal); // 0x549720
  void CreateAndSendTurnEvent20_ShortAndTwoBytes(short eventParam, unsigned char byteA,
                                                 unsigned char byteB); // 0x5495e0
  void CreateAndSendTurnEvent21_ThreeBytes(unsigned char byte0, unsigned char byte1,
                                           unsigned char byte2); // 0x549680
  void DispatchTurnEvent1AWithNationActionPayload(short param0, short param1, short param2,
                                                  short param3, short param4); // 0x5497b0
  void DispatchTaggedGameStateEvent1F20(int packetTag, int param2,
                                        int nationSlotOrMode); // 0x54a340
  void DispatchCityRedrawInvalidateEvent(short cityId);        // 0x54abf0
  void DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation,
                                              int mode);                     // 0x54c5a0
  undefined4 ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet); // 0x545940
  // Genuinely empty in the shipped binary (single `RET 4`); called by
  // TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup with the new battle view,
  // discarding both the argument and the (unset) return value. 0x54c660, __thiscall.
  void NoOpCallbackRet4(void* param);

  // Unlike the emitters above, `this` IS used here: called as
  // g_pGameFlowState->EnsureGameFlowStateAndPostTurnEvent5E5() where g_pGameFlowState may
  // still be null (every real call site loads ECX from that global first, even when it's
  // null -- non-virtual calls don't dereference `this`). Lazily constructs+installs a
  // fresh TMultiplayerMgr into g_pGameFlowState if it was null, then (whether freshly
  // constructed or already present) registers it as an idle cohandler and posts turn
  // event 0x5e5. Safe to call through a null `this` since member access only happens
  // after the null check. 0x544540.
  void EnsureGameFlowStateAndPostTurnEvent5E5();

  // Stores the turn-state pair and recomputes pendingNationBitmask from which of the
  // first kNationSlotCount terrain descriptor slots are populated. Every callsite
  // (TSimMgr::AdvanceGlobalTurnStateMachine) loads ECX from g_pGameFlowState, so this is
  // a real TMultiplayerMgr method, not a free function. 0x543120.
  void ConfigureTurnResumeStateAndNationMask(int pendingNationSlot, int activeNationSlot);

  // Refresh defaultNationTextSlots/nationDisplayNameSlots/nationStatusTags for one slot,
  // or all seven when nationSlot == -1 (dead slots get 'dead'; ineligible names are
  // wrapped in parentheses and the tag set to 'deca'). 0x54cc00 (Ghidra mis-attributed
  // it to TToolBarCluster).
  void RefreshNationStatusLabelsAndCodesForSlotOrAll(int nationSlot);

  // Send the turn-event-0x15 diplomacy need-state snapshot for nationSlot (broadcast
  // when broadcastFlag != 0). 0x54b5d0.
  void EmitNationDiplomacyNeedStateSnapshotEvent15(char broadcastFlag, int nationSlot);
};

ASSERT_SIZE(TMultiplayerMgr, 0xf8);

// 0x0054ab20. Free __stdcall sibling of TMultiplayerMgr::DispatchCityRedrawInvalidateEvent (no
// `this` -- reads g_pGlobalMapState directly instead): builds and sends a turn event carrying
// a raw snapshot of terrainStateTable[tileIndex]. RET 4 (callee-cleaned) proves __stdcall, not
// Ghidra's default __cdecl label. Defined in TMultiplayerMgr.cpp.
extern "C" void __stdcall DispatchTileRedrawInvalidateEvent(short tileIndex);
