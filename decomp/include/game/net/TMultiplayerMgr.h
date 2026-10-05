#pragma once

#include "compat.h"
#include "game/game_phase.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TEventHandler.h"
#include "game/mfc.h"
#include "game/news_domain_types.h"
#include "game/map/TMapMgr.h"

class TStream;
class TTacticalUnit;
class TTacticalBattle;
struct NetMessage;
struct TurnEventQueuePacket;
struct TurnEvent2SyncPacket;

struct TMultiplayerSlotHandle {
  unsigned char* allocatedData;
  int tagOrSize;

  TMultiplayerSlotHandle();
  ~TMultiplayerSlotHandle();
};

// VTABLE: IMPERIALISM 0x0065c030
class TMultiplayerMgr : public TEventHandler {
public:
  DECLARE_DYNCREATE(TMultiplayerMgr)
  enum { kMajorNationSessionSlotCount = 7 };

  TMultiplayerSlotHandle nationStatusControlSlots[4]; // +0x20
  TView* lobbyDialogView; // +0x40
  TEventHandler* diplomacyQueueContext;
  int nationSessionIds[kMajorNationSessionSlotCount]; // +0x48
  int queueSyncDword;                                 // +0x64
  char processPrimaryEventQueue;                      // +0x68
  bool processSecondaryEventQueue;                    // +0x69
  unsigned char pad6a[2];
  TurnEventQueuePacket* primaryTurnEventQueueHead;              // +0x6c
  TurnEventQueuePacket* secondaryTurnEventQueueHead;            // +0x70
  CString gameNameString;                                       // +0x74
  CString defaultNationTextSlots[kMajorNationSessionSlotCount]; // +0x78
  CString nationDisplayNameSlots[kMajorNationSessionSlotCount]; // +0x94
  CString playerNameString;                                     // +0xb0
  CString playerNameMirror;                                     // +0xb4
  CString fieldb8;                                              // +0xb8
  int nationStatusTags[kMajorNationSessionSlotCount]; // +0xbc — four-cc tags ('suna', 'lwoa', …)
  int sessionPhaseTag;                // +0xd8 — four-cc phase tag ('adam', 'init', …)
  unsigned char activeNationTagIndex; // +0xdc
  unsigned char padDd[3];
  int scenarioSelectionTag;       // +0xe0 — four-cc from the code-0xe session-init packet
                                  // ('load', 'rand', 'scn0'..'szz9')
  unsigned char sessionReadyFlag; // +0xe4
  unsigned char padE5[3];
  int pendingNationBitmask; // +0xe8 — one bit per nation slot; the turn-state machine
  eGamePhaseNewStyle resumePhase;
  eGamePhaseNewStyle syncPhase;
  unsigned char fieldF4; // +0xf4
  unsigned char padF5[3];

  virtual ~TMultiplayerMgr() override;             // slot 0x01 0x5427e0
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x542ff0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x542be0
  virtual void Free() override;                    // slot 0x07 0x542b10
  virtual char DoIdle(int action) override;        // slot 0x13 0x544e30
  // ORACLE: Mac TMultiplayerMgr::IMultiplayerMgr(long). Windows stores the argument in
  // TEventHandler::idleFrequencyTicks; every observed caller passes zero.
  virtual void IMultiplayerMgr(int idleFrequency); // slot 0x25 0x542900

  TMultiplayerMgr();

  void EmitTurnEvent3Mode18WithActiveNation(); // 0x5446a0
  void EmitTurnEvent10ForFlaggedNationSlots(); // 0x544720
  unsigned char CloseLobbyDialogAndEmitTurnEvent3();
  void EmitTurnEvent26DiplomacyMatrixSnapshot();
  TurnEventQueuePacket* PopTimelyMessage();
  TurnEventQueuePacket* PopVerbalMessage();
  void QueueVerbalMessage(TurnEventQueuePacket* packet);
  bool IsTimelyMessage(NetMessage* packet);
  void AppendNodeToTurnEventLinkedListAt6C(TurnEventQueuePacket* node);
  void InstallCohandler(TEventHandler* nContext, bool fEnable);
  void DispatchTurnEventCode9WithTwoTextTokens(int reasonCode, int field1CValue,
                                               const char* senderText, const char* messageText);
  unsigned char ResetNationStatusSlotsAndInitializeNameControls(TView* panel);
  enum TurnEvent11MapOffsetBase { kTurnEvent11TerrainStateBase = 0, kTurnEvent11CityScoreBase = 1 };
  void DoGameDataHunk(TurnEvent2SyncPacket* packet);      // 0x5447e0
  char UpdatePendingNationMaskIfChanged(int* cachedMask); // 0x544810
  void CreateAndSendTurnEvent11_MapOffsetAndFlags(unsigned char flagByte,
                                                  TurnEvent11MapOffsetBase mapOffsetBase,
                                                  const void* mapEntry, short shortA,
                                                  short shortB);      // 0x5493c0
  void SendChangeProvinceOwner(short provinceIndex, short nationTag); // 0x5494b0

  char AreAllSessionSlotsOwnedByActiveNation();
  void SendNewsEvent(int nationSlot, NewsEvent* event); // 0x549540 (Mac oracle)
  void CreateAndSendTurnEvent1B_FiveShortsAndDword(short shortA, short shortB, short shortC,
                                                   short shortD, short shortE,
                                                   int trailingValue); // 0x5498d0
  void SendDealResults(bool broadcastFlag, short shortA, short shortB,
                                                 short shortC, short shortD, short shortE,
                                                 short shortF);                      // 0x5499b0
  void CreateAndSendTurnEvent22_ByteAndShort(unsigned char byteVal, short shortVal); // 0x549720
  void CreateAndSendTurnEvent20_ShortAndTwoBytes(short eventParam, unsigned char byteA,
                                                 unsigned char byteB); // 0x5495e0
  void CreateAndSendTurnEvent21_ThreeBytes(unsigned char byte0, unsigned char byte1,
                                           unsigned char byte2); // 0x549680
  void SendTradeOffer(short respondingNation, short offeringNation, short proposedAmount,
                      short maxAmount, short commodityType); // 0x5497b0
  void SendStreamObject(unsigned long payloadTag, TObject* payloadObject,
                        int destinationSlot); // 0x549a90
  void DispatchTaggedGameStateEvent1F20(int packetTag, int value,
                                        int nationSlotOrMode); // 0x54a340
  // Event-8 lobby text packet: source slot plus the manager's player-name pair.
  void DispatchLobbyTextPairEvent8(unsigned char sourceNationSlot); // 0x54a410
  void CreateAndSendTurnEvent0C_Text256AndTwoFlags(CString* text, unsigned char firstFlag,
                                                   unsigned char secondFlag); // 0x54aa10
  void DispatchCityRedrawInvalidateEvent(short cityId);                       // 0x54abf0
  void DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation,
                                              int mode);                        // 0x54c5a0
  unsigned char ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet); // 0x545940
  unsigned char ResetLocalUiStateAndShowMultiplayerSetup(); // 0x545660
  unsigned char ResetGameFlowStateAndShowMainMenu(); // 0x544f30
  unsigned char ValidateGameFlowNameAndSelectionContext(int protocolValue,
                                                        int flag); // 0x544fc0
  unsigned char ValidateAndPrepareGameFlowNameForDispatch(); // 0x544ff0
  unsigned char
  InitializeRuntimeSelectionCredentialsFromProviderAndConnect(TView* provider); // 0x545110
  unsigned char ResetSessionAndShowMainMenu(); // 0x545290
  unsigned char Host(); // 0x545480
  unsigned char ApplyJoinGameSelectionAndShowNetworkGameOptions(int selectionTag); // 0x545320
  void ResetDiplomacyRuntimeSelectionAndSetModeNada(); // 0x544630
  unsigned char InitializeProtocolOptionControlFromProvider(TView* provider); // 0x544e70
  void SetDialogModeTagInitAndInvokeNoOpHook(); // 0x54c630
  void NoOpCallbackRet4(void* param);
  void EmitTacticalCommandPacket(int commandTag, TTacticalUnit* unit, int arg3,
                                 int arg4);         // 0x54c680
  void SendTacticalBattle(TTacticalBattle* battle); // 0x54c6c0
  void EmitTacticalFireCommandPacket(int commandTag, TTacticalUnit* attackerUnit,
                                     TTacticalUnit* targetUnit, int damageA, int damageB,
                                     int effectCode);         // 0x54c6a0
  void DiscardPlayer(int nationId);                           // 0x54c7d0
  bool WaitForClients();                                      // 0x54cb80
  void ResetNationStatusArraysAndTurnEventContext();          // 0x54c6e0
  unsigned char HandleActiveNationAwolTransitionOrRecovery(); // 0x54c800
  void CreateAndQueueTurnEventPacketTagPOGC();                // 0x54cde0
  void CreateAndSendTurnEvent2D_TableRowShortArray(short nationSlot,
                                                   int destinationSlot); // 0x54d3d0
  void RouteAndProcessDiplomacyTurnStateEventQueue();                    // 0x545730

  void EnsureGameFlowStateAndShowMultiplayerSetup();

  bool IsEverybodyConnected() const; // 0x00543100
  void SetSyncPhases(eGamePhaseNewStyle completedPhase, eGamePhaseNewStyle nextPhase); // 0x543120

  void HandleDiplomacyTurnEventPacketByCode();
  void ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(int nationSlot);
  void HandleTurnResumeStateTelemetry();
  void EmitTurnEventEAnd9SessionContextPackets(NetMessage* packet);
  void HandleTurnEventCodes28_2E_2F_30_31_32(TStream* stream);
  void ReceiveStreamMessage(NetMessage* packet);
  void CreateMilitaryRecruitOrdersForSelectedTerrain(TStream* stream, short nationSlot);
  void CreateCivilianWorkOrdersForSelectedNations(TStream* stream, short nationSlot);
  void ReplaceNationStateForSlotAndRefreshStatus(int nationSlot);
  unsigned char AttemptSave(int mode, char* label, bool showFailureDialog);
  void RefreshNationStatusLabelsAndCodesForSlotOrAll(int nationSlot);

  void EmitNationDiplomacyNeedStateSnapshotEvent15(bool broadcastFlag, int nationSlot);

  void SetNationStatusCodeAndEmitEvent25(int statusTag, int nationSlot);

  void EmitTurnEvent19NationStateArraysForSlot(short nationSlot, int destinationSlot);

  void EmitTurnEvent2CNationStateCompositeForSlot(int nationSlot, int destinationSlot);

  void PublishTerrainDescriptorAndNotifyOrderListeners(TStream* stream, int terrainSlot);
  void PublishNationDescriptorAndNotifyOrderListeners(TStream* stream, int nationFilter);
  void WriteMessageTo(TStream* stream, short eventTag, short destinationSlot, long payload);
  void SendStreamMessage(short eventTag, short destinationSlot, long payload); // 0x549ad0
  void SendTradeBook();
  void SetNationStatusAwolByNationIdAndDispatchNotices(int networkId);
  int IsSpecialNationDialogModeActive();
  int GetNationStatusCodeForSlotOrActiveNation(int slot);
  void RefreshPoseMessageDialogNationSelectionControls(int unused);
};

int FindNationSlotIndexBySessionIdInGameFlowList(int sessionId);
int FindActiveNationSlotIndexInGameFlowList();
// Always-true networking credential-init stub. 0x5e34b0.
bool ReturnTrueRuntimeCredentialInitStub();

ASSERT_SIZE(TMultiplayerMgr, 0xf8);

extern "C" void __stdcall DispatchTileRedrawInvalidateEvent(short tileIndex);
