#include "game/gfx/TAmbitApplication.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_tags_screens.h"
#include "game/ui_tags_widgets.h"
#include "game/resource_domain_types.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/net/TMadnessButton.h"
#include <string.h>
#include <time.h>
#include "decomp_types.h"
#include "game/core/CString.h"
#include "game/assets/TAssetMgr.h"
#include "game/military/mapped_flavor_text.h"
#include "game/military/NetMessage.h"
#include "game/multiplayer_packets.h"
#include "game/ImperialismApp.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TMinor.h"
#include "game/city/TCity.h"
#include "game/military/TCancelGameOptionsCommand.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/core/THandleStream.h"
#include "game/core/TCountingStream.h"
#include "game/ui_core/CIterator.h"
#include "game/city/TPopulationMgr.h"
#include "game/city/TProductionOrder.h"
#include "game/net/TNetMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/gfx/TResourceMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/navy/TOcean.h"
#include "game/map/TZone.h"
#include "game/military_ui/TNextDiplomationCommand.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/net_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/net/TLoungeDialog.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_core/TPicture.h"
#include "game/net/TPoseMessageDialog.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/ui_screens/TTextPictureButton.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include <cstdlib>
#include <cstring>

// Cross/UMissionSubs.cpp session and lobby lifecycle extent (0x5421a0-0x545930).

// FUNCTION: IMPERIALISM 0x00542170
int FindNationSlotIndexBySessionIdInGameFlowList(int sessionId) {
  int slot = 0;
  while (slot < TMultiplayerMgr::kMajorNationSessionSlotCount) {
    if (g_pGameFlowState->nationSessionIds[slot] == sessionId) {
      return slot;
    }
    ++slot;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x005421a0
int FindActiveNationSlotIndexInGameFlowList() {
  int activeId = g_pNetMgr->GetSessionActiveNationId();
  for (int i = 0; i < 7; ++i) {
    if (g_pGameFlowState->nationSessionIds[i] == activeId) {
      return i;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x005421e0
const char* GetGamePhaseNameString(int gamePhase) {
  switch (gamePhase) {
  case -1:
    return "kPhNoPhase";
  case 1:
    return "kPhInitializeGame";
  case 2:
    return "kPhKickOff";
  case 3:
    return "kPhCitySiteSelection";
  case 4:
    return "kPhMap";
  case 5:
    return "kPhWaitingToEndTurn";
  case 6:
    return "kPhEverybodyDoDiplomacy";
  case 7:
    return "kPhEverybodyDoTrade";
  case 8:
    return "kPhEverybodyDoCity";
  case 9:
    return "kPhEverybodyDoCivilians";
  case 10:
    return "kPhEverybodyDoMilitary";
  case 11:
    return "kPhMoneyLenders";
  case 12:
    return "kPhDealBook";
  case 13:
    return "kPhStratBatReport";
  case 14:
    return "kPhCouncilVoting";
  case 15:
    return "kPhNewspaper";
  case 16:
    return "kPhStartTurn";
  case 17:
    return "kPhTechnology";
  case 18:
    return "kPhStartMap";
  case 19:
    return "kPhMultiSync";
  case 20:
    return "kPhCombat";
  case 21:
    return "kPhFinishMilitary";
  case 22:
    return "kPhCouncilVictory";
  case 23:
    return "kPhCouncilDefeat";
  case 24:
    return "kPhMapEdit";
  case 25:
    return "kPhCheckForLosses";
  case 100:
    return "kOptPhDealBook";
  case 101:
    return "kOptPhStratBatReport";
  case 102:
    return "kOptPhNewspaper";
  case 103:
    return "kOptPhTrade";
  case 104:
    return "kOptPhDiplomacy";
  case 105:
    return "kOptPhTransport";
  case 106:
    return "kOptPhCity";
  case 107:
    return "kOptPhGameOptions";
  case 108:
    return "kOptPhShowUnitHistory";
  case 109:
    return "kOptPhTechStore";
  case 110:
    return "kOptPhGameStatus";
  case 111:
    return "kOptPhSaveGame";
  case 112:
    return "kOptPhLoadGame";
  case 113:
    return "kOptPhCredits";
  case 114:
    return "kOptPhMultiplayerLounge";
  }
  return "?";
}

IMPLEMENT_DYNCREATE(TMultiplayerMgr, TObject)

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr()
    : TEventHandler(), gameNameString(), defaultNationTextSlots(), nationDisplayNameSlots(),
      playerNameString(), playerNameMirror(), fieldb8() {
  lobbyDialogView = 0;
  primaryTurnEventQueueHead = 0;
  secondaryTurnEventQueueHead = 0;
  sessionPhaseTag = kControlTagNada;
  networkSavePending = 0;
}

// FUNCTION: IMPERIALISM 0x00542810
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
void TMultiplayerMgr::IMultiplayerMgr(int idleFrequency) {
  this->IEventHandler(NULL);
  idleFrequencyTicks = idleFrequency;
  diplomacyQueueContext = 0;
  sessionReadyFlag = 0;
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = true;

  TNetMgr* queueStorage = new TNetMgr();
  g_pNetMgr = queueStorage;
  g_pNetMgr->StartMultiplayerSupport();

  CString loadedString;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);

  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    nationSessionIds[i] = 0;
    nationStatusTags[i] = kSessionTagUnas;
    nationDisplayNameSlots[i] = loadedString;
    defaultNationTextSlots[i] = nationDisplayNameSlots[i];
  }

  queueSyncDword = 0;
  resumePhase = kGamePhaseNone;
  syncPhase = kGamePhaseNone;
  g_pNetMgr->ResetTurnEventQueueRuntimeRecordBuffer();

  GenerateMappedFlavorTextByCurrentContextNation(&playerNameString);
  LoadProfileStringAndAssignSharedRef(&loadedString, s_PlayerName,
                                      static_cast<LPCSTR>(playerNameString));
  playerNameString = loadedString;
  playerNameMirror = playerNameString;

  GenerateMappedFlavorTextByCurrentContextNation(&gameNameString);
  LoadProfileStringAndAssignSharedRef(&loadedString, s_GameName,
                                      static_cast<LPCSTR>(gameNameString));
  gameNameString = loadedString;
}

// FUNCTION: IMPERIALISM 0x00542b10
void TMultiplayerMgr::Free() {
  {
    CString playerName(playerNameString);
    g_pAssetMgr->SetPreferenceString(&playerName, s_PlayerName);
  }
  g_pAmbitApplication->InstallCohandler(this, false);
  g_pGameFlowState = 0;
  g_pNetMgr->Free();
  g_pNetMgr = 0;
  diplomacyQueueContext = 0;
  TEventHandler::Free();
}

// FUNCTION: IMPERIALISM 0x00542be0
void TMultiplayerMgr::ReadFrom(TStream* stream) {
  TEventHandler::ReadFrom(stream);

  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    stream->ReadBytes(&nationSessionIds[i], 4);
    if (nationSessionIds[i] != 0) {
      nationSessionIds[i] = -2;
      nationStatusTags[i] = IMPERIALISM_FOURCC('l', 'w', 'o', 'a');
    } else {
      nationStatusTags[i] = IMPERIALISM_FOURCC('s', 'u', 'n', 'a');
    }

    if (g_apTerrainTypeDescriptorTable[i] == NULL) {
      nationStatusTags[i] = IMPERIALISM_FOURCC('d', 'e', 'a', 'd');
    } else {
      if (!g_pSimMgr->ReallyInTheGame(static_cast<NationSlot>(i))) {
        nationStatusTags[i] = IMPERIALISM_FOURCC('a', 'c', 'e', 'd');
      }
    }

    stream->ReadSharedString(&defaultNationTextSlots[i], 0x20);
    stream->ReadSharedString(&nationDisplayNameSlots[i], 0x20);
  }

  stream->ReadSharedString(&playerNameString, 0x20);
  CString tempStr;
  stream->ReadSharedString(&tempStr, 0x20);
  stream->ReadBytes(&queueSyncDword, 4);
  stream->ReadBytes(&sessionReadyFlag, 1);

  g_pNetMgr->ReadFrom(stream);

  int sessionActiveNationId = g_pNetMgr->GetSessionActiveNationId();
  nationSessionIds[g_pSimMgr->GetPlayerCountry()] = sessionActiveNationId;

  int reportingNationSlot = g_pSimMgr->GetPlayerCountry();
  reportingNationSlot += g_pSimMgr->GetEconomicTurn() * 8;
  TurnEvent1FStatusPacket reportPacket;
  reportPacket.messageTag = kControlTagTime;
  reportPacket.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  reportPacket.eventCode = 0x1f;
  reportPacket.fromNetworkId = 0;
  reportPacket.toNetworkId = 0;
  reportPacket.messageLength = 0;
  reportPacket.messageLength = 0x20;
  reportPacket.DestinateTo(-1);
  reportPacket.statusTag = kControlTagRepo;
  reportPacket.controlValue = reportingNationSlot;
  g_pNetMgr->Send(&reportPacket, false);

  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
    sessionPhaseTag = IMPERIALISM_FOURCC('i', 'n', 'i', 't');
    g_pNetMgr->NoOpDialogModeTagChangedHook(1);
  }

  int activeIdx = g_pSimMgr->GetPlayerCountry();
  int currentIdx = activeIdx;
  if (currentIdx == -1) {
    currentIdx = static_cast<signed char>(activeNationTagIndex);
  }
  nationStatusTags[currentIdx] = IMPERIALISM_FOURCC('b', 'u', 's', 'y');

  NationStatusEvent25Packet statusPacket;
  statusPacket.messageTag = kControlTagTime;
  statusPacket.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  statusPacket.eventCode = 0x25;
  statusPacket.fromNetworkId = 0;
  statusPacket.toNetworkId = 0;
  statusPacket.messageLength = 0;
  statusPacket.messageLength = 0x34;
  for (int k = 0; k < 7; ++k) {
    statusPacket.statusTags[k] = kSessionTagUnkn;
  }
  statusPacket.statusTags[currentIdx] = kSessionTagBusy;
  g_pNetMgr->Send(&statusPacket, false);

  sessionPhaseTag = IMPERIALISM_FOURCC('g', 'o', 'i', 'n');

  int destinationNationSlot = g_pSimMgr->GetPlayerCountry();
  TurnEvent1FStatusPacket namePacket;
  namePacket.messageTag = kControlTagTime;
  namePacket.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  namePacket.eventCode = 0x1f;
  namePacket.fromNetworkId = 0;
  namePacket.toNetworkId = 0;
  namePacket.messageLength = 0;
  namePacket.messageLength = 0x20;
  if (destinationNationSlot == -1) {
    namePacket.toNetworkId = -1;
  } else if (destinationNationSlot != -2 && destinationNationSlot != -3) {
    namePacket.toNetworkId = g_pGameFlowState->nationSessionIds[destinationNationSlot];
  }
  namePacket.statusTag = kControlTagName;
  namePacket.controlValue = -1;
  g_pNetMgr->Send(&namePacket, destinationNationSlot == -3);
}

// FUNCTION: IMPERIALISM 0x00542ff0
void TMultiplayerMgr::WriteTo(TStream* stream) {
  TEventHandler::WriteTo(stream);
  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    stream->WriteBytes(&nationSessionIds[i], 4);
    stream->WriteSharedString(&defaultNationTextSlots[i]);
    stream->WriteSharedString(&nationDisplayNameSlots[i]);
  }
  stream->WriteSharedString(&playerNameString);
  stream->WriteSharedString(&gameNameString);
  stream->WriteBytes(&queueSyncDword, 4);
  stream->WriteBytes(&sessionReadyFlag, 1);
  if (g_pNetMgr != NULL) {
    g_pNetMgr->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x005430c0
void TMultiplayerMgr::InstallCohandler(TEventHandler* nContext, bool fEnable) {
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = true;
  if (fEnable != '\0') {
    diplomacyQueueContext = nContext;
    return;
  }
  diplomacyQueueContext = 0;
}

// FUNCTION: IMPERIALISM 0x00543100
bool TMultiplayerMgr::IsEverybodyConnected() const {
  return pendingNationBitmask == 0;
}

// FUNCTION: IMPERIALISM 0x00543120
void TMultiplayerMgr::SetSyncPhases(eGamePhaseNewStyle completedPhase,
                                    eGamePhaseNewStyle nextPhase) {
  syncPhase = completedPhase;
  resumePhase = nextPhase;
  pendingNationBitmask = 0;
  for (int nationSlot = 0; nationSlot < kMajorNationSessionSlotCount; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] != NULL) {
      pendingNationBitmask |= 1 << nationSlot;
    }
  }
}

struct TurnEvent3Mode18Packet : TimelyMessageHeader {};

// FUNCTION: IMPERIALISM 0x005431a0
void TMultiplayerMgr::ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(int nationSlot) {
  pendingNationBitmask &= ~(1 << nationSlot);
  bool hosting = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
  if (hosting) {
    TurnEvent1PendingMaskPacket packet;
    packet.messageTag = kControlTagTime;
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
    packet.eventCode = 0;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.eventCode = 1;
    packet.messageLength = 0;
    packet.messageLength = 0x1c;
    packet.toNetworkId = 0;
    packet.pendingMask = pendingNationBitmask;
    g_pNetMgr->Send(&packet, false);
  }
  if (pendingNationBitmask == 0 && syncPhase != kGamePhaseNone) {
    HandleDiplomacyTurnEventPacketByCode();
  }
}

// FUNCTION: IMPERIALISM 0x00544540
void TMultiplayerMgr::EnsureGameFlowStateAndShowMultiplayerSetup() {
  TMultiplayerMgr* self = this;
  if (self == 0) {
    self = new TMultiplayerMgr();
    g_pGameFlowState = self;
    if (self != 0) {
      self->IMultiplayerMgr(0);
    }
    self = g_pGameFlowState;
  }
  if (self == 0) {
    return;
  }

  ReturnTrueRuntimeCredentialInitStub();
  g_pAmbitApplication->InstallCohandler(self, true);
  g_pAmbitApplication->PostTurnEventCodeMessage(
      EncodeTurnEventCode(kTurnEventMultiplayerGameSetup));
  self->sessionPhaseTag = kSessionTagPrep; // 'prep'
}

// FUNCTION: IMPERIALISM 0x00544630
void TMultiplayerMgr::ResetDiplomacyRuntimeSelectionAndSetModeNada() {
  g_pAmbitApplication->InstallCohandler(g_pGameFlowState, false);
  g_pSimMgr->multiplayerSessionRole = kSessionRoleStandalone;
  if (g_pNetMgr != 0) {
    g_pNetMgr->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = kControlTagNada; // 'nada'
  lobbyDialogView = 0;
}

// FUNCTION: IMPERIALISM 0x005446a0
void TMultiplayerMgr::EmitTurnEvent3Mode18WithActiveNation() {
  TurnEvent3Mode18Packet packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.eventCode = 3;
  packet.messageLength = 0x18;
  g_pNetMgr->Send(&packet, true);
}

// FUNCTION: IMPERIALISM 0x00544720
void TMultiplayerMgr::EmitTurnEvent10ForFlaggedNationSlots() {
  for (int slot = 0; slot < kMajorNationSessionSlotCount; ++slot) {
    if (nationSessionIds[slot] != 0 && (pendingNationBitmask & (1 << slot)) != 0) {
      TurnEvent3Mode18Packet packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.messageLength = 0;
      packet.eventCode = 0x10;
      packet.messageLength = 0x18;
      packet.toNetworkId = g_pGameFlowState->nationSessionIds[slot];
      g_pNetMgr->Send(&packet, false);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005447e0
void TMultiplayerMgr::DoGameDataHunk(TurnEvent2SyncPacket* packet) {
  if (!packet->flag20) {
    g_pDiplomacyTurnStateManager->HandleDiplomaticStandingsMsg(packet);
  }
}

// FUNCTION: IMPERIALISM 0x00544810
bool TMultiplayerMgr::UpdatePendingNationMaskIfChanged(int* cachedMask) {
  int currentMask = pendingNationBitmask;
  if (currentMask == *cachedMask) {
    return false;
  }
  *cachedMask = currentMask;
  return true;
}

// FUNCTION: IMPERIALISM 0x00544e30
bool TMultiplayerMgr::DoIdle(int action) {
  if (diplomacyQueueContext != 0) {
    diplomacyQueueContext->DoIdle(action);
  }
  RouteAndProcessDiplomacyTurnStateEventQueue();
  return false;
}

// ---------------------------------------------------------------------------
// Turn-event emitters. Each builds a 'time'-tagged NetMessage-derived packet on
// the stack and hands it to TNetMgr::Send (queueOnly per callsite). `this` is
// unused, exactly as in the original __thiscall bodies.
// ---------------------------------------------------------------------------

// FUNCTION: IMPERIALISM 0x00544e70
bool TMultiplayerMgr::InitializeProtocolOptionControlFromProvider(TView* provider) {
  lobbyDialogView = provider;
  if (g_pNetMgr->ResetRuntimeProtocolOptionsAndRebuildSelectionSource(provider)) {
    int defaultProtocolTag;
    g_pAssetMgr->LoadSettingValueByKeyIntoOut(&defaultProtocolTag, "DefaultProtocol",
                                              kControlTagPro0);
    TRadioTextCluster* protControl =
        static_cast<TRadioTextCluster*>(provider->ResolveControlByTag(kControlTagProt));
    protControl->AssertValid();
    TView* defaultOption = protControl->ResolveControlByTag(defaultProtocolTag);
    if (defaultOption != 0) {
      protControl->SetSelectedTextOptionByTag(defaultProtocolTag, true);
    } else {
      protControl->SetSelectedTextOptionByTag(kControlTagPro0, true);
    }
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00544f30
bool TMultiplayerMgr::ResetGameFlowStateAndShowMainMenu() {
  lobbyDialogView = 0;
  g_pAmbitApplication->InstallCohandler(g_pGameFlowState, false);
  g_pSimMgr->multiplayerSessionRole = kSessionRoleStandalone;
  if (g_pNetMgr != 0) {
    g_pNetMgr->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = kControlTagNada; // 'nada'
  lobbyDialogView = 0;
  g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventMainMenu));
  return true;
}

// FUNCTION: IMPERIALISM 0x00544fc0
bool TMultiplayerMgr::ValidateGameFlowNameAndSelectionContext(int protocolValue, int flag) {
  return g_pNetMgr->OpenRuntimeSelectionSourceByIndexAndCopyPath(
      protocolValue, flag, static_cast<LPCSTR>(gameNameString));
}

// FUNCTION: IMPERIALISM 0x00544ff0
bool TMultiplayerMgr::ValidateAndPrepareGameFlowNameForDispatch() {
  CString gameName;
  gameName = gameNameString;
  g_pAssetMgr->SetPreferenceString(&gameName, s_GameName);

  int now;
  do {
    now = static_cast<int>(time(0));
    queueSyncDword = now;
  } while (now == 0);

  unsigned char opened = g_pNetMgr->Host(static_cast<LPCSTR>(gameName),
                                         static_cast<LPCSTR>(playerNameString), g_szEmptyString);
  if (opened) {
    lobbyDialogView = NULL;
    g_pSimMgr->multiplayerSessionRole = kSessionRoleHost;
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00545110
unsigned char
TMultiplayerMgr::InitializeRuntimeSelectionCredentialsFromProviderAndConnect(TView* provider) {
  ReturnTrueRuntimeCredentialInitStub();
  lobbyDialogView = provider;

  TEditText* nameControl = static_cast<TEditText*>(provider->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  CString normalizedPlayerName = g_pLanguageMgr->StripCodeStr(playerNameString);
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&normalizedPlayerName, 0);

  TEditText* passControl = static_cast<TEditText*>(provider->ResolveControlByTag(kControlTagPass));
  passControl->AssertValid();
  CString emptyCaption(g_szEmptyString);
  passControl->InitDialogWindowAndSyncTitleIfChanged(&emptyCaption, 0);

  return g_pNetMgr->ReturnTrueRuntimeCredentialFinalizeStub();
}

// FUNCTION: IMPERIALISM 0x00545290
bool TMultiplayerMgr::ResetSessionAndShowMainMenu() {
  lobbyDialogView = 0;
  g_pAmbitApplication->InstallCohandler(g_pGameFlowState, false);
  g_pSimMgr->multiplayerSessionRole = kSessionRoleStandalone;
  if (g_pNetMgr != 0) {
    g_pNetMgr->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = kControlTagNada; // 'nada'
  lobbyDialogView = 0;
  g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventMainMenu));
  return true;
}

// FUNCTION: IMPERIALISM 0x00545320
bool TMultiplayerMgr::ApplyJoinGameSelectionAndShowNetworkGameOptions(int selectionTag) {
  CString defaultGameName("Frog");
  unsigned char joined = g_pNetMgr->SelectGame(selectionTag, &playerNameString, defaultGameName);
  if (joined) {
    playerNameMirror = playerNameString;
    lobbyDialogView = 0;
    g_pSimMgr->multiplayerSessionRole = kSessionRoleClient;
    g_pAmbitApplication->PostTurnEventCodeMessage(
        EncodeTurnEventCode(kTurnEventNetworkGameOptions));
    return true;
  }
  playerNameString = playerNameMirror;
  return false;
}

// FUNCTION: IMPERIALISM 0x00545480
unsigned char TMultiplayerMgr::Host() {
  playerNameMirror = playerNameString;
  lobbyDialogView = 0;
  return 1;
}

// FUNCTION: IMPERIALISM 0x005454b0
bool TMultiplayerMgr::ResetNationStatusSlotsAndInitializeNameControls(TView* panel) {
  lobbyDialogView = panel;
  CString loadedString;
  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    nationSessionIds[i] = 0;
    nationStatusTags[i] = kSessionTagUnas; // 'unas'
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);
    TStaticText* nameControl =
        static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagNam0 + i)); // 'nam0'-'nam6'
    nameControl->AssertValid();
    nameControl->SetTextAndMaybeRefresh(&loadedString, true);
  }

  TView* okayControl = panel->ResolveControlByTag(kControlTagOkay); // 'okay'
  okayControl->AssertValid();
  okayControl->Show(0, 0);

  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleClient) {
    TurnEvent3Mode18Packet packet;
    packet.messageTag = kControlTagTime; // 'time'
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
    packet.eventCode = 0;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.eventCode = 0xd;
    packet.toNetworkId = -1;
    packet.messageLength = 0;
    packet.messageLength = 0x18;
    g_pNetMgr->Send(&packet, false);
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00545660
bool TMultiplayerMgr::ResetLocalUiStateAndShowMultiplayerSetup() {
  lobbyDialogView = 0;
  ResetNationStatusArraysAndTurnEventContext();
  g_pAmbitApplication->PostTurnEventCodeMessage(
      EncodeTurnEventCode(kTurnEventMultiplayerGameSetup));
  queueSyncDword = 0;
  return true;
}

// FUNCTION: IMPERIALISM 0x005456a0
bool TMultiplayerMgr::CloseLobbyDialogAndEmitTurnEvent3() {
  lobbyDialogView = 0;

  TurnEvent3Mode18Packet packet;
  packet.messageTag = kControlTagTime; // 'time'
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.messageLength = 0x18;
  packet.eventCode = 3;
  g_pNetMgr->Send(&packet, true);
  g_pNetMgr->NoOpDialogModeTagChangedHook(0);
  return true;
}

// FUNCTION: IMPERIALISM 0x00545730
void TMultiplayerMgr::RouteAndProcessDiplomacyTurnStateEventQueue() {
  if (processPrimaryEventQueue == 0) {
    return;
  }

  if (syncPhase != kGamePhaseNone) {
    while (primaryTurnEventQueueHead != 0) {
      TurnEventQueuePacket* packet = primaryTurnEventQueueHead;
      primaryTurnEventQueueHead = packet->nextQueuePacket;
      if (!ProcessDiplomacyTurnStateEventStateMachine(packet)) {
        g_pNetMgr->DefaultUnhandledTurnEventHookReturnsFalse(packet);
      }
      g_pNetMgr->FreeTurnEventPacketBuffer(packet);
    }
  }

  if (processSecondaryEventQueue) {
    while (secondaryTurnEventQueueHead != 0) {
      TurnEventQueuePacket* packet = secondaryTurnEventQueueHead;
      secondaryTurnEventQueueHead = packet->nextQueuePacket;
      if (!ProcessDiplomacyTurnStateEventStateMachine(packet)) {
        g_pNetMgr->DefaultUnhandledTurnEventHookReturnsFalse(packet);
      }
      g_pNetMgr->FreeTurnEventPacketBuffer(packet);
    }
  }

  TurnEventQueuePacket* packet = g_pNetMgr->PopNextTurnEventPacketOrProcessSpecialQueueRecords();
  while (packet != 0) {
    bool deferUntilTurnEvent = false;
    if (syncPhase == kGamePhaseNone) {
      switch (packet->eventCode) {
      case 1:
      case 2:
      case 6:
      case 0xa:
      case 0xb:
      case 0xf:
      case 0x18:
      case 0x19:
      case 0x1a:
      case 0x2e:
      case 0x2f:
      case 0x30:
        deferUntilTurnEvent = true;
        break;
      }
    }

    if (deferUntilTurnEvent) {
      packet->nextQueuePacket = 0;
      TurnEventQueuePacket** tail = &primaryTurnEventQueueHead;
      while (*tail != 0) {
        tail = &(*tail)->nextQueuePacket;
      }
      *tail = packet;
    } else if (!processSecondaryEventQueue && packet->eventCode == 0xc) {
      packet->nextQueuePacket = 0;
      TurnEventQueuePacket** tail = &secondaryTurnEventQueueHead;
      while (*tail != 0) {
        tail = &(*tail)->nextQueuePacket;
      }
      *tail = packet;
    } else {
      if (!ProcessDiplomacyTurnStateEventStateMachine(packet)) {
        g_pNetMgr->DefaultUnhandledTurnEventHookReturnsFalse(packet);
      }
      g_pNetMgr->FreeTurnEventPacketBuffer(packet);
    }
    packet = g_pNetMgr->PopNextTurnEventPacketOrProcessSpecialQueueRecords();
  }
}

// Receive-side state machine for every diplomacy/lobby turn event ('time' packets).
// Dispatches on eventCode 1..0x32 (codes 4..7 return 0); each case applies the payload
// to the local session/world state and often re-broadcasts or acknowledges. Case bodies
// are laid out in the original binary order.
