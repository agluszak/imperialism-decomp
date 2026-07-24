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
#include "game/ui_screens/CString.h"
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
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/military/TArmyMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TZone.h"
#include "game/military_ui/TNextDiplomationCommand.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/prelude.h"
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
#include "game/turn_event_dialog_provisional.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include <cstdlib>
#include <cstring>

// Cross/UMissionSubs.cpp session and lobby lifecycle extent (0x5421a0-0x545930).
char ReturnTrueRuntimeCredentialInitStub();

// FUNCTION: IMPERIALISM 0x005421a0
int FindActiveNationSlotIndexInGameFlowList() {
  int activeId = g_pNetMgr006a6014->GetSessionActiveNationId();
  for (int i = 0; i < 7; ++i) {
    if (g_pGameFlowState->nationSessionIds[i] == activeId) {
      return i;
    }
  }
  return -1;
}

// SYNTHETIC: IMPERIALISM 0x005425d0
// TMultiplayerMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00542650
// TMultiplayerMgr::GetRuntimeClass

// Binary descriptor base is TObject (0x694eb8), not TEventHandler — original macro arg.
IMPLEMENT_DYNCREATE(TMultiplayerMgr, TObject)

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr()
    : TEventHandler(), gameNameString(), defaultNationTextSlots(), nationDisplayNameSlots(),
      playerNameString(), playerNameMirror(), fieldb8() {
  InitializeUiResourceEntryBaseHeaderDefaults();
  lobbyDialogView40 = 0;
  primaryTurnEventQueueHead = 0;
  secondaryTurnEventQueueHead = 0;
  sessionPhaseTag = kControlTagNada;
  fieldF4 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005427e0
// TMultiplayerMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00542810
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
void TMultiplayerMgr::InitializeMultiplayerManagerForSessionContext(int sessionContext) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  field10 = sessionContext;
  diplomacyQueueContext = 0;
  sessionReadyFlag = 0;
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;

  TNetMgr* queueStorage = new TNetMgr();
  g_pNetMgr006a6014 = queueStorage;
  g_pNetMgr006a6014->StartMultiplayerSupport();

  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);

  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    nationSessionIds[i] = 0;
    nationStatusTags[i] = kSessionTagUnas;
    nationDisplayNameSlots[i] = loadedString;
    defaultNationTextSlots[i] = nationDisplayNameSlots[i];
  }

  queueSyncDword = 0;
  activeNationSlotIndex = -1;
  pendingNationSlotIndex = -1;
  g_pNetMgr006a6014->ResetTurnEventQueueRuntimeRecordBuffer();

  GenerateMappedFlavorTextByCurrentContextNation(&playerNameString);
  LoadProfileStringAndAssignSharedRef(&loadedString, s_PlayerName_0069801c,
                                      static_cast<LPCSTR>(playerNameString));
  playerNameString = loadedString;
  playerNameMirror = playerNameString;

  GenerateMappedFlavorTextByCurrentContextNation(&gameNameString);
  LoadProfileStringAndAssignSharedRef(&loadedString, s_GameName_00698010,
                                      static_cast<LPCSTR>(gameNameString));
  gameNameString = loadedString;
}

// FUNCTION: IMPERIALISM 0x00542b10
void TMultiplayerMgr::Free() {
  {
    CString playerName(playerNameString);
    g_pUiViewManager->SaveSettingValueFromPointerByKey(&playerName, s_PlayerName_0069801c);
  }
  g_pGlobalUiRootController->InstallCohandler(this, 0);
  g_pGameFlowState = 0;
  g_pNetMgr006a6014->Free();
  g_pNetMgr006a6014 = 0;
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

    if (g_apTerrainTypeDescriptorTable[i] == nullptr) {
      nationStatusTags[i] = IMPERIALISM_FOURCC('d', 'e', 'a', 'd');
    } else {
      if (!g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<NationSlot>(i))) {
        nationStatusTags[i] = IMPERIALISM_FOURCC('a', 'c', 'e', 'd');
      }
    }

    stream->streamSlot70(&defaultNationTextSlots[i], 0x20);
    stream->streamSlot70(&nationDisplayNameSlots[i], 0x20);
  }

  stream->streamSlot70(&playerNameString, 0x20);
  CString tempStr;
  stream->streamSlot70(&tempStr, 0x20);
  stream->ReadBytes(&queueSyncDword, 4);
  stream->ReadBytes(&sessionReadyFlag, 1);

  if (g_pNetMgr006a6014 != nullptr) {
    g_pNetMgr006a6014->ReadFrom(stream);
  }

  int activeId = g_pNetMgr006a6014->GetSessionActiveNationId();
  short netSlot = g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  nationSessionIds[netSlot] = activeId;
  g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  g_pSimMgr->DiplomacyNoticeString(nullptr);
  g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();

  if (g_pSimMgr->multiplayerSessionRole == 1) {
    sessionPhaseTag = IMPERIALISM_FOURCC('i', 'n', 'i', 't');
    g_pNetMgr006a6014->NoOpDialogModeTagChangedHook(1);
  }

  short activeIdx = g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  int currentIdx = activeIdx;
  if (currentIdx == -1) {
    currentIdx = activeNationTagIndex;
  }
  nationStatusTags[currentIdx] = IMPERIALISM_FOURCC('b', 'u', 's', 'y');

  g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();

  int targetStatus[7];
  for (int k = 0; k < 7; ++k) {
    targetStatus[k] = IMPERIALISM_FOURCC('u', 'n', 'k', 'n');
  }
  targetStatus[currentIdx] = IMPERIALISM_FOURCC('b', 'u', 's', 'y');

  sessionPhaseTag = IMPERIALISM_FOURCC('g', 'o', 'i', 'n');

  g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  g_pNetMgr006a6014->CheckConnectivityOrShowLocalizedWarningAndReturnReady();
}

// FUNCTION: IMPERIALISM 0x00542ff0
void TMultiplayerMgr::WriteTo(TStream* stream) {
  TEventHandler::WriteTo(stream);
  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    stream->WriteBytesSlot78(&nationSessionIds[i], 4);
    stream->streamSlotAc(&defaultNationTextSlots[i]);
    stream->streamSlotAc(&nationDisplayNameSlots[i]);
  }
  stream->streamSlotAc(&playerNameString);
  stream->streamSlotAc(&gameNameString);
  stream->WriteBytesSlot78(&queueSyncDword, 4);
  stream->WriteBytesSlot78(&sessionReadyFlag, 1);
  if (g_pNetMgr006a6014 != nullptr) {
    g_pNetMgr006a6014->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x005430c0
void TMultiplayerMgr::EnableDiplomacyQueueRoutingAndSetContextField44(void* nContext,
                                                                      char fEnable) {
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;
  if (fEnable != '\0') {
    diplomacyQueueContext = nContext;
    return;
  }
  diplomacyQueueContext = 0;
}

// FUNCTION: IMPERIALISM 0x00543120
void TMultiplayerMgr::ConfigureTurnResumeStateAndNationMask(int pendingNationSlot,
                                                            int activeNationSlot) {
  pendingNationSlotIndex = pendingNationSlot;
  activeNationSlotIndex = activeNationSlot;
  pendingNationBitmask = 0;
  for (int nationSlot = 0; nationSlot < kMajorNationSessionSlotCount; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] != nullptr) {
      pendingNationBitmask |= 1 << nationSlot;
    }
  }
}

struct TurnEvent3Mode18Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
};

// Clear the slot's turn-resume pending bit; when hosting, broadcast the remaining mask
// as an event-1 packet, and once the mask drains (with a pending event code latched)
// flush it through the diplomacy turn-event dispatcher.
// FUNCTION: IMPERIALISM 0x005431a0
void TMultiplayerMgr::ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(int nationSlot) {
  pendingNationBitmask &= ~(1 << nationSlot);
  unsigned char hosting = g_pSimMgr->multiplayerSessionRole == 1;
  if (hosting != 0) {
    TurnEvent1PendingMaskPacket packet;
    packet.messageTag = kControlTagTime;
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    packet.eventCode = 0;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.eventCode = 1;
    packet.messageLength = 0;
    packet.messageLength = 0x1c;
    packet.toNetworkId = 0;
    packet.pendingMask = pendingNationBitmask;
    g_pNetMgr006a6014->Send(&packet, 0);
  }
  if (pendingNationBitmask == 0 && pendingNationSlotIndex != -1) {
    HandleDiplomacyTurnEventPacketByCode();
  }
}

// FUNCTION: IMPERIALISM 0x00544540
void TMultiplayerMgr::EnsureGameFlowStateAndPostTurnEvent5E5() {
  TMultiplayerMgr* self = this;
  if (self == 0) {
    self = new TMultiplayerMgr();
    g_pGameFlowState = self;
    if (self != 0) {
      self->InitializeMultiplayerManagerForSessionContext(0);
    }
    self = g_pGameFlowState;
  }
  if (self == 0) {
    return;
  }

  ReturnTrueRuntimeCredentialInitStub();
  g_pGlobalUiRootController->InstallCohandler(self, 1);
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
      EncodeTurnEventCode(kTurnEventMultiplayerGameSetup));
  self->sessionPhaseTag = kSessionTagPrep; // 'prep'
}

// FUNCTION: IMPERIALISM 0x00544630
void TMultiplayerMgr::ResetDiplomacyRuntimeSelectionAndSetModeNada() {
  g_pGlobalUiRootController->InstallCohandler(g_pGameFlowState, 0);
  g_pSimMgr->multiplayerSessionRole = 0;
  if (g_pNetMgr006a6014 != 0) {
    g_pNetMgr006a6014->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = kControlTagNada; // 'nada'
  lobbyDialogView40 = 0;
}

// FUNCTION: IMPERIALISM 0x005446a0
void TMultiplayerMgr::EmitTurnEvent3Mode18WithActiveNation() {
  TurnEvent3Mode18Packet packet;
  packet.packetTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.eventCode = 3;
  packet.messageLength = 0x18;
  g_pNetMgr006a6014->Send(&packet, 1);
}

// Broadcasts an event-0x10 "time" packet (same minimal payload as event 3) to every nation
// slot that has both a live network session id and its pending-nation bit set.
// FUNCTION: IMPERIALISM 0x00544720
void TMultiplayerMgr::EmitTurnEvent10ForFlaggedNationSlots() {
  for (int slot = 0; slot < kMajorNationSessionSlotCount; ++slot) {
    if (nationSessionIds[slot] != 0 && (pendingNationBitmask & (1 << slot)) != 0) {
      TurnEvent3Mode18Packet packet;
      packet.packetTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.messageLength = 0;
      packet.eventCode = 0x10;
      packet.messageLength = 0x18;
      packet.toNetworkId = g_pGameFlowState->nationSessionIds[slot];
      g_pNetMgr006a6014->Send(&packet, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00544e30
char TMultiplayerMgr::DoIdle(int action) {
  (void)action;
  return 0;
}

// ---------------------------------------------------------------------------
// Turn-event emitters. Each builds a 'time'-tagged NetMessage-derived packet on
// the stack and hands it to TNetMgr::Send (queueOnly per callsite). `this` is
// unused, exactly as in the original __thiscall bodies.
// ---------------------------------------------------------------------------

// FUNCTION: IMPERIALISM 0x00544e70
unsigned char TMultiplayerMgr::InitializeProtocolOptionControlFromProvider(TView* provider) {
  lobbyDialogView40 = provider;
  if (!g_pNetMgr006a6014->ResetRuntimeProtocolOptionsAndRebuildSelectionSource(provider)) {
    return 0;
  }

  int defaultProtocolTag = 0;
  g_pUiViewManager->LoadSettingValueByKeyIntoOut(&defaultProtocolTag, "DefaultProtocol",
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
  return 1;
}

// FUNCTION: IMPERIALISM 0x00544f30
unsigned char TMultiplayerMgr::ResetGameFlowStateAndPostTurnEvent5DC() {
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->InstallCohandler(g_pGameFlowState, 0);
  g_pSimMgr->multiplayerSessionRole = 0;
  if (g_pNetMgr006a6014 != 0) {
    g_pNetMgr006a6014->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = kControlTagNada; // 'nada'
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(EncodeTurnEventCode(kTurnEventMainMenu));
  return 1;
}

// FUNCTION: IMPERIALISM 0x00544fc0
unsigned char TMultiplayerMgr::ValidateGameFlowNameAndSelectionContext(int protocolValue,
                                                                       int flag) {
  return g_pNetMgr006a6014->OpenRuntimeSelectionSourceByIndexAndCopyPath(
      protocolValue, flag, static_cast<LPCSTR>(gameNameString));
}

// FUNCTION: IMPERIALISM 0x00544ff0
unsigned char TMultiplayerMgr::ValidateAndPrepareGameFlowNameForDispatch() {
  CString gameName;
  gameName = gameNameString;
  g_pUiViewManager->SaveSettingValueFromPointerByKey(&gameName, s_GameName_00698010);

  int now;
  do {
    now = static_cast<int>(time(0));
    queueSyncDword = now;
  } while (now == 0);

  unsigned char opened = g_pNetMgr006a6014->OpenRuntimeSelectionSourceAndApplyActiveNationState(
      static_cast<LPCSTR>(gameName), static_cast<LPCSTR>(playerNameString), g_szEmptyString);
  if (opened) {
    lobbyDialogView40 = nullptr;
    g_pSimMgr->multiplayerSessionRole = 1;
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00545110
unsigned char
TMultiplayerMgr::InitializeRuntimeSelectionCredentialsFromProviderAndConnect(TView* provider) {
  ReturnTrueRuntimeCredentialInitStub();
  lobbyDialogView40 = provider;

  TEditText* nameControl = static_cast<TEditText*>(provider->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  CString normalizedPlayerName =
      g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&playerNameString);
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&normalizedPlayerName, 0);

  TEditText* passControl = static_cast<TEditText*>(provider->ResolveControlByTag(kControlTagPass));
  passControl->AssertValid();
  CString emptyCaption(g_szEmptyString);
  passControl->InitDialogWindowAndSyncTitleIfChanged(&emptyCaption, 0);

  return g_pNetMgr006a6014->ReturnTrueRuntimeCredentialFinalizeStub();
}

// FUNCTION: IMPERIALISM 0x00545290
unsigned char TMultiplayerMgr::ResetGameFlowStateAndPostTurnEvent5DCAlt() {
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->InstallCohandler(g_pGameFlowState, 0);
  g_pSimMgr->multiplayerSessionRole = 0;
  if (g_pNetMgr006a6014 != 0) {
    g_pNetMgr006a6014->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = kControlTagNada; // 'nada'
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(EncodeTurnEventCode(kTurnEventMainMenu));
  return 1;
}

// FUNCTION: IMPERIALISM 0x00545320
unsigned char TMultiplayerMgr::ApplyJoinGameSelectionAndPostTurnEvent5E4(int selectionTag) {
  CString defaultGameName("Frog");
  unsigned char joined = g_pNetMgr006a6014->OpenJoinGameRuntimeSelectionAndStartSession(
      selectionTag, &playerNameString, defaultGameName);
  if (joined) {
    playerNameMirror = playerNameString;
    lobbyDialogView40 = 0;
    g_pSimMgr->multiplayerSessionRole = 2;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventNetworkGameOptions));
    return 1;
  }
  playerNameString = playerNameMirror;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00545480
unsigned char TMultiplayerMgr::AssignStringAtB4FromB0AndResetState40() {
  playerNameMirror = playerNameString;
  lobbyDialogView40 = 0;
  return 1;
}

// FUNCTION: IMPERIALISM 0x005454b0
unsigned char TMultiplayerMgr::ResetNationStatusSlotsAndInitializeNameControls(TView* panel) {
  lobbyDialogView40 = panel;
  CString loadedString;
  for (int i = 0; i < kMajorNationSessionSlotCount; ++i) {
    nationSessionIds[i] = 0;
    nationStatusTags[i] = kSessionTagUnas; // 'unas'
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);
    TStaticText* nameControl =
        static_cast<TStaticText*>(panel->ResolveControlByTag(kControlTagNam0 + i)); // 'nam0'-'nam6'
    nameControl->AssertValid();
    nameControl->SetTextAndMaybeRefresh(&loadedString, 1);
  }

  TView* okayControl = panel->ResolveControlByTag(kControlTagOkay); // 'okay'
  okayControl->AssertValid();
  okayControl->SetEnabled(0, 0);

  if (g_pSimMgr->multiplayerSessionRole == 2) {
    TurnEvent3Mode18Packet packet;
    packet.packetTag = kControlTagTime; // 'time'
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    packet.eventCode = 0;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.eventCode = 0xd;
    packet.toNetworkId = -1;
    packet.messageLength = 0;
    packet.messageLength = 0x18;
    g_pNetMgr006a6014->Send(&packet, 0);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00545660
unsigned char TMultiplayerMgr::ResetLocalUiStateAndPostTurnEvent5E5() {
  lobbyDialogView40 = 0;
  ResetNationStatusArraysAndTurnEventContext();
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
      EncodeTurnEventCode(kTurnEventMultiplayerGameSetup));
  queueSyncDword = 0;
  return 1;
}

// FUNCTION: IMPERIALISM 0x005456a0
unsigned char TMultiplayerMgr::CloseLobbyDialogAndEmitTurnEvent3() {
  lobbyDialogView40 = 0;

  TurnEvent3Mode18Packet packet;
  packet.packetTag = kControlTagTime; // 'time'
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.messageLength = 0x18;
  packet.eventCode = 3;
  g_pNetMgr006a6014->Send(&packet, 1);
  g_pNetMgr006a6014->NoOpDialogModeTagChangedHook(0);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00545730
void TMultiplayerMgr::RouteAndProcessDiplomacyTurnStateEventQueue() {
  if (processPrimaryEventQueue == 0) {
    return;
  }

  if (pendingNationSlotIndex != -1) {
    while (primaryTurnEventQueueHead != 0) {
      TurnEventQueuePacket* packet = primaryTurnEventQueueHead;
      primaryTurnEventQueueHead = packet->nextQueuePacket;
      if (ProcessDiplomacyTurnStateEventStateMachine(packet) == 0) {
        g_pNetMgr006a6014->DefaultUnhandledTurnEventHookReturnsFalse(packet);
      }
      g_pNetMgr006a6014->FreeTurnEventPacketBuffer(packet);
    }
  }

  if (processSecondaryEventQueue != 0) {
    while (secondaryTurnEventQueueHead != 0) {
      TurnEventQueuePacket* packet = secondaryTurnEventQueueHead;
      secondaryTurnEventQueueHead = packet->nextQueuePacket;
      if (ProcessDiplomacyTurnStateEventStateMachine(packet) == 0) {
        g_pNetMgr006a6014->DefaultUnhandledTurnEventHookReturnsFalse(packet);
      }
      g_pNetMgr006a6014->FreeTurnEventPacketBuffer(packet);
    }
  }

  TurnEventQueuePacket* packet =
      g_pNetMgr006a6014->PopNextTurnEventPacketOrProcessSpecialQueueRecords();
  while (packet != 0) {
    unsigned char deferUntilTurnEvent = 0;
    if (pendingNationSlotIndex == -1) {
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
        deferUntilTurnEvent = 1;
        break;
      }
    }

    if (deferUntilTurnEvent != 0) {
      packet->nextQueuePacket = 0;
      TurnEventQueuePacket** tail = &primaryTurnEventQueueHead;
      while (*tail != 0) {
        tail = &(*tail)->nextQueuePacket;
      }
      *tail = packet;
    } else if (processSecondaryEventQueue == 0 && packet->eventCode == 0xc) {
      packet->nextQueuePacket = 0;
      TurnEventQueuePacket** tail = &secondaryTurnEventQueueHead;
      while (*tail != 0) {
        tail = &(*tail)->nextQueuePacket;
      }
      *tail = packet;
    } else {
      if (ProcessDiplomacyTurnStateEventStateMachine(packet) == 0) {
        g_pNetMgr006a6014->DefaultUnhandledTurnEventHookReturnsFalse(packet);
      }
      g_pNetMgr006a6014->FreeTurnEventPacketBuffer(packet);
    }
    packet = g_pNetMgr006a6014->PopNextTurnEventPacketOrProcessSpecialQueueRecords();
  }
}

// Receive-side state machine for every diplomacy/lobby turn event ('time' packets).
// Dispatches on eventCode 1..0x32 (codes 4..7 return 0); each case applies the payload
// to the local session/world state and often re-broadcasts or acknowledges. Case bodies
// are laid out in the original binary order.
