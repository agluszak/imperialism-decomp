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

  TMultiplayerSlotHandle nationStatusControlSlots[4];
  TView* lobbyDialogView;
  TEventHandler* diplomacyQueueContext;
  int nationSessionIds[kMajorNationSessionSlotCount];
  int queueSyncDword;
  char processPrimaryEventQueue;
  bool processSecondaryEventQueue;
  unsigned char pad6a[2];
  TurnEventQueuePacket* primaryTurnEventQueueHead;
  TurnEventQueuePacket* secondaryTurnEventQueueHead;
  CString gameNameString;
  CString defaultNationTextSlots[kMajorNationSessionSlotCount];
  CString nationDisplayNameSlots[kMajorNationSessionSlotCount];
  CString playerNameString;
  CString playerNameMirror;
  CString fieldb8;
  int nationStatusTags[kMajorNationSessionSlotCount]; // four-cc tags ('suna', 'lwoa', …)
  int sessionPhaseTag;                                // four-cc phase tag ('adam', 'init', …)
  unsigned char activeNationTagIndex;
  unsigned char padDd[3];
  int scenarioSelectionTag; // four-cc from the code-0xe session-init packet
                            // ('load', 'rand', 'scn0'..'szz9')
  unsigned char sessionReadyFlag;
  unsigned char padE5[3];
  int pendingNationBitmask; // one bit per nation slot; the turn-state machine
  eGamePhaseNewStyle resumePhase;
  eGamePhaseNewStyle syncPhase;
  unsigned char networkSavePending;
  unsigned char padF5[3];

  virtual ~TMultiplayerMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  virtual bool DoIdle(int action) override;
  // ORACLE: Mac TMultiplayerMgr::IMultiplayerMgr(long); the argument is the idle frequency.
  virtual void IMultiplayerMgr(int idleFrequency);

  TMultiplayerMgr();

  void EmitTurnEvent3Mode18WithActiveNation();
  void SendGoAheadMessage();
  bool CloseLobbyDialogAndEmitTurnEvent3();
  void EmitTurnEvent26DiplomacyMatrixSnapshot();
  TurnEventQueuePacket* PopTimelyMessage();
  TurnEventQueuePacket* PopVerbalMessage();
  void QueueVerbalMessage(TurnEventQueuePacket* packet);
  bool IsTimelyMessage(NetMessage* packet);
  void QueueTimelyMessage(TurnEventQueuePacket* node);
  void InstallCohandler(TEventHandler* nContext, bool fEnable);
  void SendGpSelection(int reasonCode, int field1CValue, const char* senderText,
                       const char* messageText);
  bool ResetNationStatusSlotsAndInitializeNameControls(TView* panel);
  enum TurnEvent11MapOffsetBase { kTurnEvent11TerrainStateBase = 0, kTurnEvent11CityScoreBase = 1 };
  void DoGameDataHunk(TurnEvent2SyncPacket* packet);
  bool UpdatePendingNationMaskIfChanged(int* cachedMask);
  void SendMapPoke(signed char pokeWidthCode, TurnEvent11MapOffsetBase mapOffsetBase,
                   const void* mapEntry, short pokeValue, short pokeMask);
  void SendChangeProvinceOwner(short provinceIndex, short nationTag);

  bool AreAllSessionSlotsOwnedByActiveNation();
  void SendNewsEvent(int nationSlot, NewsEvent* event);
  void SendDealBookEntry(short nationSlot, short trackedKind, short targetNation,
                         short trackedValue, short trackedSlotIndex, int trackedPayload);
  void SendDealResults(bool broadcast, short sourceNation, short targetNation, short amount,
                       short maximumAmount, short commodityType, short shortfallFlag);
  void SendNewsMiscEvent(unsigned char nationSlotOrAll, short storyCode);
  void SendNewsTreatyEvent(short eventKind, unsigned char nationA, unsigned char nationB);
  void SendNewsShortageEvent(unsigned char subjectNation, unsigned char affectedNation,
                             unsigned char relatedNation);
  void SendTradeOffer(short respondingNation, short offeringNation, short proposedAmount,
                      short maxAmount, short commodityType);
  void SendStreamObject(unsigned long payloadTag, TObject* payloadObject, int destinationSlot);
  void SendGameControl(int statusTag, int value, int nationSlotOrMode);
  // Event-8 lobby text packet: source slot plus the manager's player-name pair.
  void DispatchLobbyTextPairEvent8(unsigned char sourceNationSlot);
  void SendVerbalMessage(CString* text, unsigned char firstFlag, unsigned char secondFlag);
  void DispatchCityRedrawInvalidateEvent(short cityId);
  void SendChangeMaster(int sourceNation, int targetNation, int mode);
  bool ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet);
  bool ResetLocalUiStateAndShowMultiplayerSetup();
  bool ResetGameFlowStateAndShowMainMenu();
  bool ValidateGameFlowNameAndSelectionContext(int protocolValue, int flag);
  bool ValidateAndPrepareGameFlowNameForDispatch();
  unsigned char InitializeRuntimeSelectionCredentialsFromProviderAndConnect(TView* provider);
  bool ResetSessionAndShowMainMenu();
  unsigned char Host();
  bool ApplyJoinGameSelectionAndShowNetworkGameOptions(int selectionTag);
  void ResetDiplomacyRuntimeSelectionAndSetModeNada();
  bool InitializeProtocolOptionControlFromProvider(TView* provider);
  void SetDialogModeTagInitAndInvokeNoOpHook();
  void NoOpCallbackRet4(void* param);
  void SendTacLa(int commandTag, TTacticalUnit* unit, int arg3, int arg4);
  void SendTacticalBattle(TTacticalBattle* battle);
  void SendTacLaEx(int commandTag, TTacticalUnit* attackerUnit, TTacticalUnit* targetUnit,
                   int damageA, int damageB, int effectCode);
  void DiscardPlayer(int nationId);
  bool WaitForClients();
  void ResetNationStatusArraysAndTurnEventContext();
  bool HandleActiveNationAwolTransitionOrRecovery();
  void CreateAndQueueTurnEventPacketTagPOGC();
  void SendMinorStateMessage(short nationSlot, int destinationSlot);
  void RouteAndProcessDiplomacyTurnStateEventQueue();

  void EnsureGameFlowStateAndShowMultiplayerSetup();

  bool IsEverybodyConnected() const;
  void SetSyncPhases(eGamePhaseNewStyle completedPhase, eGamePhaseNewStyle nextPhase);

  void HandleDiplomacyTurnEventPacketByCode();
  void ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(int nationSlot);
  void HandleTurnResumeStateTelemetry();
  void EmitTurnEventEAnd9SessionContextPackets(NetMessage* packet);
  void ReadMessageFrom(TStream* stream);
  void ReceiveStreamMessage(NetMessage* packet);
  void ReadArmyUnitsFrom(TStream* stream, short nationSlot);
  void ReadCiviliansFrom(TStream* stream, short nationSlot);
  void DehumanizePlayer(int nationSlot);
  bool AttemptSave(int mode, char* label, bool showFailureDialog);
  void RecalcPlayerName(int nationSlot);

  void SendBankStatement(bool broadcastFlag, int nationSlot);

  void SetPlayerStatus(int statusTag, int nationSlot);

  void SendNationStateMessage(short nationSlot, int destinationSlot);

  void SendCityStateMessage(int nationSlot, int destinationSlot);

  void WriteArmyUnitsTo(TStream* stream, int terrainSlot);
  void WriteCiviliansTo(TStream* stream, int nationFilter);
  void WriteMessageTo(TStream* stream, short eventTag, short destinationSlot, long payload);
  void SendStreamMessage(short eventTag, short destinationSlot, long payload);
  void SendTradeBook();
  void WeLostAClient(int networkId);
  int IsSpecialNationDialogModeActive();
  int GetPlayerStatus(int slot);
  void PoseMessageDialog(int unused);
};

int FindNationSlotIndexBySessionIdInGameFlowList(int sessionId);
int FindActiveNationSlotIndexInGameFlowList();
// Always-true networking credential-init stub.
bool ReturnTrueRuntimeCredentialInitStub();

ASSERT_SIZE(TMultiplayerMgr, 0xf8);

extern "C" void __stdcall SendTileNews(short tileIndex);
