#include "game/net/TNetMgr.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/gfx/TResourceMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TRadioTextCluster.h"

#include "game/core/CString.h"
#include "game/military/NetMessage.h"
#include "game/multiplayer_packets.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/net/TWNetSessionManager.h"
#include "game/globals/global_types.h"
#include "game/globals/net_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

#include <cstring>
#include <new>

IMPLEMENT_DYNCREATE(TNetMgr, TObject)

// FUNCTION: IMPERIALISM 0x005e33e0
TNetMgr::TNetMgr() : TObject() {}

// FUNCTION: IMPERIALISM 0x005e3430
TNetMgr::~TNetMgr() {}

// FUNCTION: IMPERIALISM 0x005e3450
void TNetMgr::StartMultiplayerSupport() {}

// FUNCTION: IMPERIALISM 0x005e3470
void TNetMgr::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x005e3490
bool TNetMgr::DefaultUnhandledTurnEventHookReturnsFalse(TurnEventQueuePacket* packet) {
  return false;
}

// FUNCTION: IMPERIALISM 0x005e34d0
bool TNetMgr::ResetRuntimeSelectionRecordBufferAndReturnTrue() {
  g_NetworkSessionManager006a5f60.ResetRuntimeSelectionRecordBuffer();
  return true;
}

// FUNCTION: IMPERIALISM 0x005e34f0
void TNetMgr::HandleError(int errorCode) {
  CString message("DirectPlay Error: ");
  switch (errorCode) {
  case DPERR_OUTOFMEMORY:
    message += "DPERR_NOMEMORY";
    break;
  case DPERR_UNSUPPORTED:
    message += "DPERR_UNSUPPORTED";
    break;
  case DPERR_NOINTERFACE:
    message += "DPERR_NOINTERFACE";
    break;
  case DPERR_GENERIC:
    message += "DPERR_GENERIC";
    break;
  case DPERR_ALREADYINITIALIZED:
    message += "DPERR_ALREADYINITIALIZED";
    break;
  case DPERR_INVALIDPARAMS:
    message += "DPERR_INVALIDPARAM";
    break;
  case DPERR_ACTIVEPLAYERS:
    message += "DPERR_ACTIVEPLAYERS";
    break;
  case DPERR_ACCESSDENIED:
    message += "DPERR_ACCESSDENIED";
    break;
  case DPERR_CANTADDPLAYER:
    message += "DPERR_CANTADDPLAYER";
    break;
  case DPERR_BUFFERTOOSMALL:
    message += "DPERR_BUFFERTOOSMALL";
    break;
  case DPERR_CANTCREATEPLAYER:
    message += "DPERR_CANTCREATEPLAYER";
    break;
  case DPERR_CANTCREATEGROUP:
    message += "DPERR_CANTCREATEGROUP";
    break;
  case DPERR_CAPSNOTAVAILABLEYET:
    message += "DPERR_CAPSNOTAVAILABLEYET";
    break;
  case DPERR_CANTCREATESESSION:
    message += "DPERR_CANTCREATESESSION";
    break;
  case DPERR_INVALIDFLAGS:
    message += "DPERR_INVALIDFLAGS";
    break;
  case DPERR_EXCEPTION:
    message += "DPERR_EXCEPTION";
    break;
  case DPERR_INVALIDPLAYER:
    message += "DPERR_INVALIDPLAYER";
    break;
  case DPERR_INVALIDOBJECT:
    message += "DPERR_INVALIDOBJECT";
    break;
  case DPERR_NOCONNECTION:
    message += "DPERR_NOCONNECTION";
    break;
  case DPERR_NOCAPS:
    message += "DPERR_NOCAPS";
    break;
  case DPERR_NONAMESERVERFOUND:
    message += "DPERR_NONAMESERVERFOUND";
    break;
  case DPERR_NOMESSAGES:
    message += "DPERR_NOMESSAGES";
    break;
  case DPERR_NOSESSIONS:
    message += "DPERR_NOSESSIONS";
    break;
  case DPERR_NOPLAYERS:
    message += "DPERR_NOPLAYERS";
    break;
  case DPERR_TIMEOUT:
    message += "DPERR_TIMEOUT";
    break;
  case DPERR_SENDTOOBIG:
    message += "DPERR_SENDTOOBIG";
    break;
  case DPERR_BUSY:
    message += "DPERR_BUSY";
    break;
  case DPERR_UNAVAILABLE:
    message += "DPERR_UNAVAILABLE";
    break;
  case DPERR_CANNOTCREATESERVER:
    message += "DPERR_CANNOTCREATESERVER";
    break;
  case DPERR_USERCANCEL:
    message += "DPERR_USERCANCEL";
    break;
  case DPERR_SESSIONLOST:
    message += "DPERR_SESSIONLOST";
    break;
  case DPERR_PLAYERLOST:
    message += "DPERR_PLAYERLOST";
    break;
  case DPERR_CANTCREATEPROCESS:
    message += "DPERR_CANTCREATEPROCESS";
    break;
  case DPERR_BUFFERTOOLARGE:
    message += "DPERR_BUFFERTOOLARGE";
    break;
  case DPERR_INVALIDINTERFACE:
    message += "DPERR_INVALIDINTERFACE";
    break;
  case DPERR_APPNOTSTARTED:
    message += "DPERR_APPNOTSTARTED";
    break;
  case DPERR_UNKNOWNAPPLICATION:
    message += "DPERR_UNKNOWNAPPLICATION";
    break;
  case DPERR_NOSERVICEPROVIDER:
    message += "DPERR_NOSERVICEPROVIDER";
    break;
  case DPERR_NOTLOBBIED:
    message += "DPERR_NOTLOBBIED";
    break;
  case DP_OK:
    message += "DP_OK";
    break;
  default: {
    CString genericMessage("A network error has occured");
    message = genericMessage;
    break;
  }
  }

  g_pViewMgr->ModalMessage(message, g_ptNetworkModalMessage);
  if (DAT_006a601c == 0) {
    ReportAssertionFailure("D:\\Ambit\\WNetMgr.cpp", 0x1c3);
  }
}

// FUNCTION: IMPERIALISM 0x005e39a0
unsigned char TNetMgr::ResetRuntimeProtocolOptionsAndRebuildSelectionSource(TView* provider) {
  g_NetworkSessionManager006a5f60.activeProtocolControl =
      static_cast<TRadioTextCluster*>(provider->FindSubView(kControlTagProt)); // 'prot'
  g_NetworkSessionManager006a5f60.activeProtocolControl->AssertValid();

  for (int index = 0; index < g_WNetSerializedPtrArrayA.GetSize(); ++index) {
    delete g_WNetSerializedPtrArrayA[index];
  }
  g_WNetSerializedPtrArrayA.RemoveAll();
  unsigned char result = g_NetworkSessionManager006a5f60.RebuildRuntimeSelectionSource();
  g_NetworkSessionManager006a5f60.activeProtocolControl = 0;
  return result;
}

// FUNCTION: IMPERIALISM 0x005e3a60
bool TNetMgr::SelectProtocol(int index, int flag, const char* seed) {
  strncpy(g_NetworkSessionManager006a5f60.runtimeSelectionSeed, seed, 32);
  const GUID* sessionGuid = &g_WNetSerializedPtrArrayA[index]->providerGuid;
  bool result =
      g_NetworkSessionManager006a5f60.InitializeDirectPlayForProviderGuidOrEnumerate(sessionGuid);
  if (!result) {
    HandleError(g_NetworkSessionManager006a5f60.lastErrorCode);
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005e3ad0
unsigned char TNetMgr::Host(const char* seedPath, const char* localPlayerName,
                            const char* emptyOrSeed) {
  strncpy(g_NetworkSessionManager006a5f60.joinGameSeed, emptyOrSeed, 32);
  strncpy(g_NetworkSessionManager006a5f60.runtimeSelectionSeed, seedPath, 32);

  int result = g_NetworkSessionManager006a5f60.OpenRuntimeSelectionSourceFromCurrentContext();
  if (result) {
    DPID nationId;
    {
      CString localName(localPlayerName);
      result = g_NetworkSessionManager006a5f60.CreatePlayerAndStoreResult(&nationId,
                                                                          localName.GetBuffer(1));
      localName.ReleaseBuffer(-1);
    }
    if (result) {
      g_NetworkSessionManager006a5f60.localPlayerId = nationId;
      g_NetworkSessionManager006a5f60.broadcastPlayerId = nationId;
      result = g_NetworkSessionManager006a5f60.SetLocalPlayerDataAndStoreResult(
          &g_NetworkSessionManager006a5f60.joinGamePlayerDataTag, 4);
    }
  }
  if (!result) {
    HandleError(g_NetworkSessionManager006a5f60.lastErrorCode);
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005e3c00
bool TNetMgr::ReturnTrueRuntimeCredentialFinalizeStub() {
  return true;
}

// FUNCTION: IMPERIALISM 0x005e3c20
unsigned char TNetMgr::SelectGame(int selectionTag, CString* outGameName, const char* seed) {
  strncpy(g_NetworkSessionManager006a5f60.joinGameSeed, seed, 32);
  g_NetworkSessionManager006a5f60.joinGamePlayerName = *outGameName;

  int result = g_NetworkSessionManager006a5f60.OpenRuntimeSelectionSourceWithUserChoice();
  if (result) {
    *outGameName = g_NetworkSessionManager006a5f60.joinGamePlayerName;

    LPSTR shortName = g_NetworkSessionManager006a5f60.joinGamePlayerName.GetBuffer(1);
    DPID localPlayerId;
    result = g_NetworkSessionManager006a5f60.CreatePlayerAndStoreResult(&localPlayerId, shortName);
    g_NetworkSessionManager006a5f60.joinGamePlayerName.ReleaseBuffer(-1);
    if (result) {
      g_NetworkSessionManager006a5f60.localPlayerId = localPlayerId;
      result = g_NetworkSessionManager006a5f60.SetLocalPlayerDataAndStoreResult(
          &g_NetworkSessionManager006a5f60.joinGamePlayerDataTag,
          sizeof(g_NetworkSessionManager006a5f60.joinGamePlayerDataTag));
      if (result) {
        result = g_NetworkSessionManager006a5f60.FindHostPlayerIdByEnumeration();
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005e3d40
bool TNetMgr::Send(NetMessage* message, bool queueOnly) {
  unsigned int sizeBytes = message->messageLength;
  message->fromNetworkId = g_NetworkSessionManager006a5f60.localPlayerId;
  int nationId = message->toNetworkId;
  if (message->toNetworkId == -1) {
    nationId = g_NetworkSessionManager006a5f60.broadcastPlayerId;
  }

  if (queueOnly || nationId == g_NetworkSessionManager006a5f60.localPlayerId) {
    void* heapCopy = GlobalAlloc(0, static_cast<DWORD>(sizeBytes));
    memcpy(heapCopy, message, sizeBytes);
    g_WNetPendingPacketList.AddTail(heapCopy);
    if (nationId == g_NetworkSessionManager006a5f60.localPlayerId) {
      return true;
    }
  }

  if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(nationId, message, sizeBytes)) {
    return true;
  }
  HandleError(g_NetworkSessionManager006a5f60.lastErrorCode);
  return false;
}

// FUNCTION: IMPERIALISM 0x005e3ef0
void TNetMgr::ResetTurnEventQueueRuntimeRecordBuffer() {
  g_NetworkSessionManager006a5f60.ResetRuntimeSelectionRecordBuffer();
}

// FUNCTION: IMPERIALISM 0x005e3f10
void TNetMgr::ReleaseMessage(TurnEventQueuePacket* packet) {
  GlobalFree(packet);
}

// FUNCTION: IMPERIALISM 0x005e3f30
TurnEventQueuePacket* TNetMgr::GetMessage() {
  if (g_NetworkSessionManager006a5f60.directPlayInterface == 0) {
    return 0;
  }
  if (!g_WNetPendingPacketList.IsEmpty()) {
    return static_cast<TurnEventQueuePacket*>(g_WNetPendingPacketList.RemoveHead());
  }

  for (;;) {
    DWORD fromId = 0;
    DWORD toId;
    void* packetBuffer = 0;
    int received = g_NetworkSessionManager006a5f60.TryReceiveNetworkPacketIntoResizableBuffer(
        &fromId, &toId, &packetBuffer);
    TurnEventQueuePacket* packet = static_cast<TurnEventQueuePacket*>(packetBuffer);
    if (received == 0 && g_NetworkSessionManager006a5f60.lastErrorCode != DPERR_NOMESSAGES) {
      HandleError(g_NetworkSessionManager006a5f60.lastErrorCode);
      return packet;
    }
    if (packet == 0 || fromId != 0) {
      if (packet != 0) {
        packet->fromNetworkId = fromId;
        packet->toNetworkId = toId;
      }
      return packet;
    }

    switch (packet->eventCode) {
    case 3:
    case 7:
    case 0x21:
    case 0x102:
    case 0x103:
      break;
    case 5:
      if (packet->fromNetworkId == 1) {
        g_pGameFlowState->WeLostAClient(packet->toNetworkId);
      }
      break;
    case 0x31:
    case 0x101:
      g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x2759, 6, 0, 0);
      g_pGameFlowState->HandleActiveNationAwolTransitionOrRecovery();
      break;
    default:
      if (g_suppressUnexpectedDirectPlaySystemMessageAssert == 0) {
        ReportAssertionFailure("D:\\Ambit\\WNetMgr.cpp", 0x2f6);
      }
      break;
    }
    GlobalFree(packet);
  }
}

// FUNCTION: IMPERIALISM 0x005e4280
int TNetMgr::GetPlayerID() {
  return g_NetworkSessionManager006a5f60.localPlayerId;
}

// FUNCTION: IMPERIALISM 0x005e42a0
void TNetMgr::NoOpDialogModeTagChangedHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005e42c0
void TNetMgr::NotifyIfNationMatchesSessionActiveNation(int nationId) {
  if (nationId == g_NetworkSessionManager006a5f60.localPlayerId) {
    g_NetworkSessionManager006a5f60.DestroyPlayerAndStoreResult(nationId);
  }
}

// FUNCTION: IMPERIALISM 0x005e42f0
bool TNetMgr::CheckConnectivityOrShowLocalizedWarningAndReturnReady() {
  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleClient &&
      g_NetworkSessionManager006a5f60.OpenCurrentSessionDescriptionForJoin()) {
    return true;
  }
  CString message;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2742, 0x19);
  g_pViewMgr->ModalMessage(message, g_ptNetworkModalMessage, 0, 0);
  return false;
}

// FUNCTION: IMPERIALISM 0x005e43e0
int TNetMgr::Ping() {
  int awolBitmask = 0;
  TurnEvent2BPresenceMaskPacket probe;
  probe.messageTag = kControlTagTime;
  probe.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  probe.eventCode = 0;
  probe.fromNetworkId = 0;
  probe.eventCode = 0x2b;
  probe.toNetworkId = 0;
  probe.messageLength = 0;
  probe.messageLength = 0x1c;
  probe.replyRequestFlag = 0;
  probe.nationMask = static_cast<signed char>(g_pSimMgr->GetPlayerCountry());
  for (int slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation != 0 && nation->diplomacyEligibility != 0 && nation->IsRemote()) {
      if (g_pGameFlowState->nationSessionIds[slot] == -2) {
        awolBitmask += 1 << slot;
      } else {
        probe.DestinateToGP(slot);
        probe.fromNetworkId = g_NetworkSessionManager006a5f60.localPlayerId;
        int destination = probe.toNetworkId;
        if (destination == -1) {
          destination = g_NetworkSessionManager006a5f60.broadcastPlayerId;
        }
        if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(destination, &probe,
                                                                 probe.messageLength) == 0) {
          awolBitmask += 1 << slot;
          g_pGameFlowState->WeLostAClient(slot);
        }
      }
    }
  }
  return awolBitmask;
}
