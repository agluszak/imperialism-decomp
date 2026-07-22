#pragma once

#include "compat.h"
#include "game/TEventHandler.h"
#include "game/mfc.h"

class TStream;
class TTacticalUnit;
struct NetMessage;

// 0xa8-byte nation-status snapshot record with a trailing shared-text CString at +0xa4,
// used as a stack local by the diplomacy turn-event packet handler (0x543910); it is also
// literally the wire body of the event-0x24 city-record packet
// (TurnEvent24CityRecordPacket::record in TMultiplayerMgr.cpp), and its case-0x24 handler
// copies field00/02/03/06/block82/A1/A2 directly into Province's
// same-named, same-offset fields (TMapMgr.h) -- so this struct is that record's serialized
// mirror, byte-for-byte. Fields below are renamed by that position-for-position
// correspondence (serialization-order evidence); byte3B/byte3C are left unrenamed because
// Province's own fields at those offsets are themselves still unresolved
// placeholders. field98/field9C stay `int` (not TMilitaryUnit*/int) since the wire copy is
// never dereferenced -- the case-0x24 handler skips them entirely when merging into the
// live record. The default ctor (0x50ec60) constructs only the CString member; the
// copy-assignment (0x54ae90) copies the POD prefix then the CString.
struct NationStateRecordA8 {
  unsigned char ownerNationCode00;
  unsigned char formerOwnerNationCode01;
  unsigned char developmentStage;
  unsigned char fortLevel03;
  short cityTileIndex04;
  short lastTurnTick;
  unsigned char adjacentRegionCount08;
  unsigned char pad09;
  short adjacentRegionIds0A[12];
  short adjacentRegionAnchorTiles22[12];
  unsigned char linkedRegionCount;
  unsigned char field3B;
  unsigned char field3C;
  unsigned char pad3D;
  short secondaryNeighborTileIndex3e;
  short primaryNeighborTileIndex40;
  short linkedRegionIds42[0x20];
  short resourceDevelopmentCounts82[10];
  short pad96;
  // reservedUnitChainSlot98/reservedCityScoreSlot9C: byte-range twin of the live record's
  // stationedUnitChain98 (TMilitaryUnit*) / cityScoreValue (int); transmitted verbatim but
  // never read back out of this wire copy.
  int reservedUnitChainSlot98;
  int reservedCityScoreSlot9C;
  unsigned char navyOrderReachableA0;
  unsigned char exploredByNationMaskA1;
  unsigned char resourcePresenceMaskA2;
  unsigned char regionClassA3;
  CString cityNameA4;

  NationStateRecordA8();
  NationStateRecordA8& operator=(const NationStateRecordA8& source);
};

// One of TMultiplayerMgr::nationStatusControlSlots' 4 elements. Ground truth from
// TMultiplayerMgr construction/destruction (0x542670/0x542810) uses VC5's vector
// iterators over four of these records. The element ctor zeroes both fields and the
// element dtor scalar-deletes the byte/POD storage when present. Neither the payload
// shape nor tagOrSize's meaning is recovered yet.
struct TMultiplayerSlotHandle {
  unsigned char* allocatedData;
  int tagOrSize;

  TMultiplayerSlotHandle();
  ~TMultiplayerSlotHandle();
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
  TView* lobbyDialogView40; // +0x40
  // +0x44 — child handler for queue routing. Opaque: TLoungeDialog::DoPostCreate
  // passes `this` (a TView-derived dialog) as the sole non-zero writer seen so far.
  void* diplomacyQueueContext;
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
  // Close the current lounge dialog, emit the loopback event-3 tick, and notify the
  // network manager that the dialog-mode tag changed. 0x5456a0.
  unsigned char CloseLobbyDialogAndEmitTurnEvent3();
  // 0x54c480 — builds a turn-event-26 packet snapshotting g_pDiplomacyTurnStateManager's
  // relation/pending-policy/selection/comparative-power matrices and hands it to
  // TNetMgr::Send. Body not yet ported (separate packet-struct modeling task); called
  // from RebuildDiplomacyStandingAndInfluenceMatrices only when g_pSimMgr->multiplayerSessionRole == 1.
  void EmitTurnEvent26DiplomacyMatrixSnapshot();
  // Appends a queue node (next pointer at node+0x10) to the tail of
  // primaryTurnEventQueueHead. 0x549280.
  void AppendNodeToTurnEventLinkedListAt6C(int node);
  // 0x5430c0 — enable both diplomacy queue-processing flags and set the routing context.
  void EnableDiplomacyQueueRoutingAndSetContextField44(void* nContext, char fEnable);
  // 0x54b4c0, RET 0x10 (4 stack args). Builds and sends a LobbyChatEvent9Packet: reasonCode
  // becomes nationSlot18 (the field's original comment names it for the AWOL use case; this
  // caller uses it as a generic status/reason byte instead), field1CValue becomes field1C,
  // senderText copies into senderName, and messageText copies into messageText (both
  // unbounded strcpy, matching the original's raw REP MOVSD/MOVSB copy). The only known
  // caller (TLoungeDialog) passes the same string for both.
  void DispatchTurnEventCode9WithTwoTextTokens(int reasonCode, int field1CValue,
                                               const char* senderText, const char* messageText);
  // 0x5454b0. Records `panel` as lobbyDialogView40, resets nationSessionIds[]/nationStatusTags[]
  // for all 7 slots, restamps each 'nam0'-'nam6' control from GetString(0x2759, 1) (index is a
  // literal 1 for every slot, not looped), resets the 'okay' control, and -- only when
  // g_pSimMgr->multiplayerSessionRole == 2 -- broadcasts a minimal event-0xd "time" packet. Always returns 1.
  unsigned char ResetNationStatusSlotsAndInitializeNameControls(TView* panel);
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
  // 0x549a90: wraps a {tag, object} pair and sends it through the event-0x31
  // serializer. Town/depot/port creation uses the 'town' tag and destination -2.
  void DispatchTurnEvent31TaggedPayload(int payloadTag, TObject* payloadObject,
                                        int destinationSlot);
  void DispatchTaggedGameStateEvent1F20(int packetTag, int param2,
                                        int nationSlotOrMode); // 0x54a340
  // Event-8 lobby text packet: source slot plus the manager's player-name pair.
  void DispatchLobbyTextPairEvent8(unsigned char sourceNationSlot); // 0x54a410
  void DispatchCityRedrawInvalidateEvent(short cityId);             // 0x54abf0
  void DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation,
                                              int mode);                        // 0x54c5a0
  unsigned char ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet); // 0x545940
  // Clear the active lobby context, rebuild the seven nation-status rows, post
  // setup event 0x5e5, and clear the queue synchronization word.
  unsigned char ResetLocalUiStateAndPostTurnEvent5E5(); // 0x545660
  // Uninstall this manager as the app's cohandler, clear the DirectPlay runtime
  // selection buffer (if a session exists), reset the phase tag to 'nada' and the
  // lobby dialog view, and post setup event 0x5dc.
  unsigned char ResetGameFlowStateAndPostTurnEvent5DC(); // 0x544f30
  // Forwards to TNetMgr's DirectPlay session-open path with this manager's
  // gameNameString as the copy-out buffer.
  unsigned char ValidateGameFlowNameAndSelectionContext(int protocolValue,
                                                        int flag); // 0x544fc0
  // Snapshots gameNameString into a temp, saves it under the "GameName" setting key,
  // stamps queueSyncDword with the current time (retried until nonzero), opens the
  // DirectPlay session via TNetMgr with playerNameString as the local player's short
  // name, and on success clears the lobby dialog view and marks the sim mode active.
  unsigned char ValidateAndPrepareGameFlowNameForDispatch(); // 0x544ff0
  // Stashes the lobby dialog `provider`, sets its 'name' field's caption to the
  // normalized local player name, and clears its 'pass' field's caption. Returns the
  // DirectPlay session finalize stub's result (always true).
  unsigned char
  InitializeRuntimeSelectionCredentialsFromProviderAndConnect(TView* provider); // 0x545110
  // Compiled twin of ResetGameFlowStateAndPostTurnEvent5DC (same body, separate
  // out-of-line copy in the binary).
  unsigned char ResetGameFlowStateAndPostTurnEvent5DCAlt(); // 0x545290
  // Hosting a new game: backs up playerNameString into playerNameMirror and clears
  // the lobby dialog view. No DirectPlay session-join step (unlike
  // ApplyJoinGameSelectionAndPostTurnEvent5E4).
  unsigned char AssignStringAtB4FromB0AndResetState40(); // 0x545480
  // Joins the DirectPlay session named by selectionTag via TNetMgr, staging
  // playerNameString as both the seed and the round-tripped result buffer. On
  // success, mirrors the resolved name, clears the lobby dialog view, marks the sim
  // client role (g_pSimMgr->multiplayerSessionRole = 2), and posts setup event 0x5e4. On failure,
  // restores playerNameString from playerNameMirror.
  unsigned char ApplyJoinGameSelectionAndPostTurnEvent5E4(int selectionTag); // 0x545320
  // Uninstalls this manager as the app's cohandler, clears the DirectPlay runtime
  // selection buffer, and resets the phase tag to 'nada' and the lobby dialog view
  // -- same as the ResetGameFlowStateAndPostTurnEvent5DC* pair but without posting
  // a setup event.
  void ResetDiplomacyRuntimeSelectionAndSetModeNada(); // 0x544630
  // Rebuilds the protocol-option list for `provider`'s 'prot' cluster and selects
  // the "DefaultProtocol" setting (falling back to 'pro0' if that tag isn't
  // present among the options).
  unsigned char InitializeProtocolOptionControlFromProvider(TView* provider); // 0x544e70
  // Genuinely empty in the shipped binary (single `RET 4`); called by
  // TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup with the new battle view,
  // discarding both the argument and the (unset) return value. 0x54c660, __thiscall.
  void SetDialogModeTagInitAndInvokeNoOpHook(); // 0x54c630
  void NoOpCallbackRet4(void* param);
  // Multiplayer tactical-command echo hooks, dispatched thiscall on g_pGameFlowState by
  // every TTacticalBattle command handler. Retail bodies are empty (0x54c680 = bare
  // `ret 0x10`, 0x54c6a0 = bare `ret 0x18`) -- the echo was compiled out.
  void EmitTacticalCommandPacket(int commandTag, TTacticalUnit* unit, int arg3,
                                 int arg4); // 0x54c680
  void EmitTacticalFireCommandPacket(int commandTag, TTacticalUnit* attackerUnit,
                                     TTacticalUnit* targetUnit, int damageA, int damageB,
                                     int effectCode); // 0x54c6a0
  void ResetNationStatusArraysAndTurnEventContext();  // 0x54c6e0

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
  // requesting session (turn-event 0xD receive path).
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

  // Update one nation-status tag (resolving -1 to the active/fallback slot) and send
  // the corresponding event-0x25 status-board delta. 0x54b7e0.
  void SetNationStatusCodeAndEmitEvent25(int statusTag, int nationSlot);

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
  // Mac oracle: SendTradeBook. Broadcasts the event-0x32 trade-book packet with no
  // payload to destination -2. 0x54b5b0.
  void SendTradeBook();
  // 0x54b930: for every session slot matching networkId - tag the nation 'awol',
  // broadcast the event-0x25 status packet, mark the session id -2 and the pending bit,
  // then either send the event-9 lobby-chat drop notice (session init) or show the
  // localized "nation has dropped" advisory and post a 'pogc' cancel command.
  void SetNationStatusAwolByNationIdAndDispatchNotices(int networkId);
  // 0x54a9d0: true when sessionPhaseTag is the 'goin' join phase and the active nation
  // slot is valid.
  int IsSpecialNationDialogModeActive();
  // 0x54b8c0: returns nationStatusTags[slot]; when slot is -1, resolves it from the active
  // nation id (falling back to the game-flow session-id scan).
  int GetNationStatusCodeForSlotOrActiveNation(int slot);
  // 0x54b1b0, RET 4 (one stack arg, unread by the body so far as ported). If the local
  // session isn't seated in nationSessionIds[] at all, poses an error prompt and returns.
  // Otherwise resolves the pose-message dialog (turn-event context 0x5e7) and, for each
  // 'box0'-'box6' slot control, marks it occupied-by-another-player via SetState.
  void RefreshPoseMessageDialogNationSelectionControls(int unused);
};

// 0x5421a0: 0-based index (0..6) of g_pGameFlowState->nationSessionIds[] matching the
// session's active nation id, or -1. Free __cdecl function.
int FindActiveNationSlotIndexInGameFlowList();

ASSERT_SIZE(TMultiplayerMgr, 0xf8);

// 0x0054ab20. Free __stdcall sibling of TMultiplayerMgr::DispatchCityRedrawInvalidateEvent (no
// `this` -- reads g_pGlobalMapState directly instead): builds and sends a turn event carrying
// a raw snapshot of terrainStateTable[tileIndex]. RET 4 (callee-cleaned) proves __stdcall, not
// Ghidra's default __cdecl label. Defined in TMultiplayerMgr.cpp.
extern "C" void __stdcall DispatchTileRedrawInvalidateEvent(short tileIndex);
