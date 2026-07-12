#pragma once

#include "compat.h"
#include "game/TEventHandler.h"
#include "game/mfc.h"

class TStream;
class TTacticalUnit;
struct NetMessage;

// 0xa8-byte nation-status snapshot record with a trailing shared-text CString at +0xa4,
// used as a stack local by the diplomacy turn-event packet handler (0x543910). The POD
// prefix mirrors the received nation/city state; interior field semantics are still
// being mapped (named by offset). The default ctor (0x50ec60) constructs only the
// CString member; the copy-assignment (0x54ae90) copies the POD prefix then the CString.
struct NationStateRecordA8 {
  unsigned char field00;
  unsigned char field01;
  unsigned char field02;
  unsigned char field03;
  short field04;
  short field06;
  unsigned char field08;
  unsigned char pad09;
  short block0A[12];
  short block22[12];
  unsigned char field3A;
  unsigned char field3B;
  unsigned char field3C;
  unsigned char pad3D;
  short field3E;
  short field40;
  short block42[0x20];
  short block82[10];
  short pad96;
  int field98;
  int field9C;
  unsigned char fieldA0;
  unsigned char fieldA1;
  unsigned char fieldA2;
  unsigned char fieldA3;
  CString sharedTextA4;

  NationStateRecordA8();
  NationStateRecordA8& operator=(const NationStateRecordA8& source);
};

// One of TMultiplayerMgr::nationStatusControlSlots' 4 elements. Ground truth from
// TMultiplayerMgr::~TMultiplayerMgr (0x542810): each slot's destructor frees dataPtr via
// a raw operator delete (no typed destructor on the pointee), gated on non-null. Neither
// the pointee type nor tagOrSize's meaning is recovered yet; no reader/writer of the
// array besides the ctor's memset zero-init is ported.
struct TMultiplayerSlotHandle {
  void* dataPtr;
  int tagOrSize;

  ~TMultiplayerSlotHandle() {
    if (dataPtr != 0) {
      operator delete(dataPtr);
    }
  }
};

// Multiplayer session / game-flow manager (g_pGameFlowState). Inherits the shared
// TEventHandler control surface used by UI roots; vtable @ 0x0065c030.
// VTABLE: IMPERIALISM 0x0065c030
class TMultiplayerMgr : public TEventHandler {
public:
  DECLARE_DYNCREATE(TMultiplayerMgr)
  enum { kNationSlotCount = 7 };

  TMultiplayerSlotHandle nationStatusControlSlots[4]; // +0x20
  // +0x40 — the active lobby dialog view when one is open; the code-9 receive path
  // checks IsKindOf(RUNTIME_CLASS(TLoungeDialog)) before using it as the lounge.
  TView* lobbyDialogView40;               // +0x40
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

  virtual ~TMultiplayerMgr() override;             // slot 0x01 0x5427e0
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x542ff0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x542be0
  virtual void Free() override;                    // slot 0x07 0x542b10
  virtual char DoIdle(int action) override;        // slot 0x13 0x544e30
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
  void EmitTurnEvent3Mode18WithActiveNation(); // 0x5446a0
  void EmitTurnEvent10ForFlaggedNationSlots(); // 0x544720
  // Appends a queue node (next pointer at node+0x10) to the tail of
  // primaryTurnEventQueueHead. 0x549280.
  void AppendNodeToTurnEventLinkedListAt6C(int node);
  void CreateAndSendTurnEvent11_MapOffsetAndFlags(unsigned char flagByte, int mapOffsetSelector,
                                                  int absoluteOffset, short shortA,
                                                  short shortB);       // 0x5493c0
  void CreateAndSendTurnEvent12_TwoShorts(short shortA, short shortB); // 0x5494b0
  void CreateAndSendTurnEvent13_NationAndNineDwords(int nationSlot,
                                                    int* payloadDwords); // 0x549540
  void CreateAndSendTurnEvent1C_BoolAndSixShorts(bool broadcastFlag, short shortA, short shortB,
                                                 short shortC, short shortD, short shortE,
                                                 short shortF);                      // 0x5499b0
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
                                              int mode);                        // 0x54c5a0
  unsigned char ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet); // 0x545940
  // Genuinely empty in the shipped binary (single `RET 4`); called by
  // TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup with the new battle view,
  // discarding both the argument and the (unset) return value. 0x54c660, __thiscall.
  void NoOpCallbackRet4(void* param);
  // Multiplayer tactical-command echo hooks, dispatched thiscall on g_pGameFlowState by
  // every TTacticalBattle command handler. Retail bodies are empty (0x54c680 = bare
  // `ret 0x10`, 0x54c6a0 = bare `ret 0x18`) -- the echo was compiled out.
  void EmitTacticalCommandPacket(int commandTag, TTacticalUnit* unit, int arg3,
                                 int arg4); // 0x54c680
  void EmitTacticalFireCommandPacket(int commandTag, TTacticalUnit* attackerUnit,
                                     TTacticalUnit* targetUnit, int damageA, int damageB,
                                     int effectCode); // 0x54c6a0

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
  // 0x543910: post-resume diplomacy turn-event dispatcher — switches on
  // pendingNationSlotIndex (the received turn-event code) and re-broadcasts the
  // matching game-state snapshot family; every path except code 6 ends with the
  // event-3 tick acknowledge.
  void HandleDiplomacyTurnEventPacketByCode();
  // 0x5431a0: clear the slot's turn-resume pending bit, broadcast the remaining mask
  // (event 1) when hosting, and flush the latched event code once the mask drains.
  void ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(int nationSlot);
  // 0x543280: turn-resume telemetry pass — hosting drops absent nations' pending bits
  // and re-broadcasts the mask; clients acknowledge the pending event code; everyone
  // marks the local nation 'redy' and broadcasts the event-0x25 status board.
  void HandleTurnResumeStateTelemetry();
  // 0x54c8e0: re-emit the event-0xE session-init + event-9 name packets for the
  // requesting session (turn-event 0xD receive path). Body TODO.
  void EmitTurnEventEAnd9SessionContextPackets(NetMessage* packet);
  // 0x549ff0: receive path for turn events 0x28/0x2E..0x32 — reads the 0x1c timely
  // header, derives the acting nation (-1 during teardown), and dispatches by event
  // code: 0x28 rebuilds the tactical battle from the stream, 0x2E resyncs the navy
  // order lists, 0x2F/0x30 rebuild military/civilian orders, 0x31 handles the
  // 'army'/'star'+'land'/'town' tagged payloads, 0x32 resyncs the trade manager.
  void HandleTurnEventCodes28_2E_2F_30_31_32(TStream* stream);
  // 0x54a6d0: deserialize the military recruit orders for the selected terrain
  // (turn-event-0x2F receive path).
  void CreateMilitaryRecruitOrdersForSelectedTerrain(TStream* stream, short nationSlot);
  // 0x54a840: deserialize the civilian work orders for the selected nations
  // (turn-event-0x30 receive path).
  void CreateCivilianWorkOrdersForSelectedNations(TStream* stream, short nationSlot);
  // 0x54bd20: replace the vacated slot's nation with a freshly rolled TAutoGreatPower
  // (deep state copy + subobject ownership swap), then drop the session id, tag the
  // slot 'suna', refresh labels, and re-broadcast the pending mask when hosting.
  void ReplaceNationStateForSlotAndRefreshStatus(int nationSlot);
  // 0x54d4e0: probe reachability, save when everyone is reachable, else optionally pose
  // the "cannot save" advisory; returns the all-reachable byte Boolean.
  unsigned char TrySaveGameAndMaybeShowFailureDialog(int mode, char* label, char showFailureDialog);
  void RefreshNationStatusLabelsAndCodesForSlotOrAll(int nationSlot);

  // Send the turn-event-0x15 diplomacy need-state snapshot for nationSlot (broadcast
  // when broadcastFlag != 0). 0x54b5d0.
  void EmitNationDiplomacyNeedStateSnapshotEvent15(char broadcastFlag, int nationSlot);

  // Send the turn-event-0x19 per-nation state-array packet for nationSlot to
  // destinationSlot (sentinels as NetMessage::DestinateTo; -3 also marks the send
  // as loopback-suppressed). 0x54d1f0.
  void EmitTurnEvent19NationStateArraysForSlot(short nationSlot, int destinationSlot);

  // Send the turn-event-0x2c composite city/population snapshot for nationSlot (no-op
  // when the nation has no city). 0x54ce80.
  void EmitTurnEvent2CNationStateCompositeForSlot(int nationSlot, int destinationSlot);

  // Serializer subtree for the turn-event packet dispatcher (0x543910 family).
  // 0x54a500: 'a'+slot marker byte, then the terrain descriptor's military unit list
  // (16-bit count + WriteTo sweep), terminated with '.'.
  void PublishTerrainDescriptorAndNotifyOrderListeners(TStream* stream, int terrainSlot);
  // 0x54a5e0: per great-power tracked-object list (count + WriteTo sweep; 0 for
  // filtered-out or empty slots).
  void PublishNationDescriptorAndNotifyOrderListeners(TStream* stream, int nationFilter);
  // 0x549c60: write the 0x1c-byte packet header then the tag-specific payload.
  void SerializeOrderDataIntoTurnEventByTag(TStream* stream, short eventTag, short destinationSlot,
                                            void* payload);
  // 0x549ad0: measure with a TCountingStream, then serialize into a THandleStream over
  // GlobalAlloc memory, stamp the real length, and send (loopback-suppressed for -3).
  void DispatchTurnEventPacketWithCodeAndPayloadBuffer(short eventTag, short destinationSlot,
                                                       void* payload);
  // 0x54b930: for every session slot matching networkId - tag the nation 'awol',
  // broadcast the event-0x25 status packet, mark the session id -2 and the pending bit,
  // then either send the event-9 lobby-chat drop notice (session init) or show the
  // localized "nation has dropped" advisory and post a 'pogc' cancel command.
  void SetNationStatusAwolByNationIdAndDispatchNotices(int networkId);
};

ASSERT_SIZE(TMultiplayerMgr, 0xf8);

// 0x0054ab20. Free __stdcall sibling of TMultiplayerMgr::DispatchCityRedrawInvalidateEvent (no
// `this` -- reads g_pGlobalMapState directly instead): builds and sends a turn event carrying
// a raw snapshot of terrainStateTable[tileIndex]. RET 4 (callee-cleaned) proves __stdcall, not
// Ghidra's default __cdecl label. Defined in TMultiplayerMgr.cpp.
extern "C" void __stdcall DispatchTileRedrawInvalidateEvent(short tileIndex);
