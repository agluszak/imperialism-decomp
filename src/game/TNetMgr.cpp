#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TGreatPower.h"

#include "game/CString.h"
#include "game/NetMessage.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/TWNetSessionManager.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

#include <cstring>
#include <new>

// SYNTHETIC: IMPERIALISM 0x005e3390
// TNetMgr::CreateObject

IMPLEMENT_DYNCREATE(TNetMgr, TObject)

// SYNTHETIC: IMPERIALISM 0x005e33c0
// TNetMgr::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x005e33e0
TNetMgr::TNetMgr() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x005e3400
// TNetMgr::`scalar deleting destructor'
TNetMgr::~TNetMgr() {}

// FUNCTION: IMPERIALISM 0x005e3470
void TNetMgr::Free() {}

static const char kDirectPlayErrorTitle[] = "DirectPlay Error";
static const char kNetworkErrorGeneric[] = "A network error has occurred.";
static const char kDirectPlayOk[] = "DirectPlay OK";

// The comparison tree mirrors the binary-search shape MSVC emitted for the original
// switch on the DPERR codes; each pivot is the largest constant of its branch + 1.
static const char* LookupDirectPlayErrorDetailText(int errorCode) {
  if (errorCode < DPERR_OUTOFMEMORY + 1) {
    if (errorCode == DPERR_OUTOFMEMORY) {
      return "Not enough memory available.";
    }
    if (errorCode == DPERR_UNSUPPORTED) {
      return "This function is not supported on this system.";
    }
    if (errorCode == DPERR_NOINTERFACE) {
      return "No such interface supported.";
    }
    if (errorCode == DPERR_GENERIC) {
      return "An undefined error code was returned from a DirectPlay function.";
    }
    return 0;
  }
  if (errorCode < DPERR_ALREADYINITIALIZED + 1) {
    if (errorCode == DPERR_ALREADYINITIALIZED) {
      return "This object is already initialized.";
    }
    if (errorCode == DPERR_INVALIDPARAMS) {
      return "One or more parameters were invalid.";
    }
    return 0;
  }
  if (errorCode < DPERR_ACTIVEPLAYERS + 1) {
    if (errorCode == DPERR_ACTIVEPLAYERS) {
      return "There are active players in the session.";
    }
    if (errorCode == DPERR_ACCESSDENIED) {
      return "Access to the object is denied.";
    }
    return 0;
  }
  if (errorCode < DPERR_CANTADDPLAYER + 1) {
    if (errorCode == DPERR_CANTADDPLAYER) {
      return "Can't add player.";
    }
    if (errorCode == DPERR_BUFFERTOOSMALL) {
      return "The buffer supplied is too small.";
    }
    return 0;
  }
  if (errorCode < DPERR_CANTCREATEPLAYER + 1) {
    if (errorCode == DPERR_CANTCREATEPLAYER) {
      return "Can't create player.";
    }
    if (errorCode == DPERR_CANTCREATEGROUP) {
      return "Can't create group.";
    }
    return 0;
  }
  if (errorCode < DPERR_CAPSNOTAVAILABLEYET + 1) {
    if (errorCode == DPERR_CAPSNOTAVAILABLEYET) {
      return "The capabilities requested are not yet available.";
    }
    if (errorCode == DPERR_CANTCREATESESSION) {
      return "Can't create session.";
    }
    return 0;
  }
  if (errorCode < DPERR_INVALIDFLAGS + 1) {
    if (errorCode == DPERR_INVALIDFLAGS) {
      return "Invalid flags were specified.";
    }
    if (errorCode == DPERR_EXCEPTION) {
      return "An exception occurred.";
    }
    return 0;
  }
  if (errorCode < DPERR_INVALIDPLAYER + 1) {
    if (errorCode == DPERR_INVALIDPLAYER) {
      return "Invalid player.";
    }
    if (errorCode == DPERR_INVALIDOBJECT) {
      return "Invalid object.";
    }
    return 0;
  }
  if (errorCode < DPERR_NOCONNECTION + 1) {
    if (errorCode == DPERR_NOCONNECTION) {
      return "No connection.";
    }
    if (errorCode == DPERR_NOCAPS) {
      return "The required capabilities are not available.";
    }
    return 0;
  }
  if (errorCode < DPERR_NONAMESERVERFOUND + 1) {
    if (errorCode == DPERR_NONAMESERVERFOUND) {
      return "No name server found.";
    }
    if (errorCode == DPERR_NOMESSAGES) {
      return "There are no messages waiting.";
    }
    return 0;
  }
  if (errorCode < DPERR_NOSESSIONS + 1) {
    if (errorCode == DPERR_NOSESSIONS) {
      return "There are no sessions available.";
    }
    if (errorCode == DPERR_NOPLAYERS) {
      return "There are no players available.";
    }
    return 0;
  }
  if (errorCode < DPERR_TIMEOUT + 1) {
    if (errorCode == DPERR_TIMEOUT) {
      return "The operation timed out.";
    }
    if (errorCode == DPERR_SENDTOOBIG) {
      return "The message is too large to send.";
    }
    return 0;
  }
  if (errorCode < DPERR_BUSY + 1) {
    if (errorCode == DPERR_BUSY) {
      return "The message queue is full.";
    }
    if (errorCode == DPERR_UNAVAILABLE) {
      return "The service is unavailable.";
    }
    return 0;
  }
  if (errorCode < DPERR_CANNOTCREATESERVER + 1) {
    if (errorCode == DPERR_CANNOTCREATESERVER) {
      return "Can't create server.";
    }
    if (errorCode == DPERR_USERCANCEL) {
      return "The user canceled the operation.";
    }
    return 0;
  }
  if (errorCode < DPERR_SESSIONLOST + 1) {
    if (errorCode == DPERR_SESSIONLOST) {
      return "The session was lost.";
    }
    if (errorCode == DPERR_PLAYERLOST) {
      return "The player was lost.";
    }
    return 0;
  }
  if (errorCode < DPERR_CANTCREATEPROCESS + 1) {
    if (errorCode == DPERR_CANTCREATEPROCESS) {
      return "Can't create process.";
    }
    if (errorCode == DPERR_BUFFERTOOLARGE) {
      return "The buffer is too large.";
    }
    return 0;
  }
  if (errorCode < DPERR_INVALIDINTERFACE + 1) {
    if (errorCode == DPERR_INVALIDINTERFACE) {
      return "Invalid interface.";
    }
    if (errorCode == DPERR_APPNOTSTARTED) {
      return "The application is not started.";
    }
    return 0;
  }
  if (errorCode < DPERR_UNKNOWNAPPLICATION + 1) {
    if (errorCode == DPERR_UNKNOWNAPPLICATION) {
      return "Unknown application.";
    }
    if (errorCode == DPERR_NOSERVICEPROVIDER) {
      return "No service provider available.";
    }
    return 0;
  }
  if (errorCode == DPERR_NOTLOBBIED) {
    return "Not lobbied.";
  }
  if (errorCode == DP_OK) {
    return kDirectPlayOk;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e34d0
unsigned char TNetMgr::ResetRuntimeSelectionRecordBufferAndReturnTrue() {
  g_NetworkSessionManager006a5f60.ResetRuntimeSelectionRecordBuffer();
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e34f0
void TNetMgr::HandleError(int errorCode) {
  CString message(kDirectPlayErrorTitle);
  const char* detailText = LookupDirectPlayErrorDetailText(errorCode);
  if (detailText == 0) {
    CString genericMessage(kNetworkErrorGeneric);
    message = genericMessage;
  } else {
    message += detailText;
  }

  g_pUiRuntimeContext->RunControlStringProviderAndDispatchLocalizedMessage(message, 0);
  if (DAT_006a601c == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
}

// FUNCTION: IMPERIALISM 0x005e39a0
unsigned char TNetMgr::ResetRuntimeProtocolOptionsAndRebuildSelectionSource(TView* provider) {
  // TODO(class-recovery): the retail body leads with
  // provider->ResolveControlByTag('prot')->AssertValid() into a scratch global
  // (0x6a6010, cleared again at the end) before this cleanup -- not modeled yet, so
  // `provider` still goes unused here. RebuildRuntimeSelectionSource itself takes no
  // argument (Ghidra-verified: bare RET).
  for (int index = 0; index < g_WNetSerializedPtrArrayA006a5f10.GetSize(); ++index) {
    delete static_cast<RuntimeSelectionRecord*>(g_WNetSerializedPtrArrayA006a5f10[index]);
  }
  g_WNetSerializedPtrArrayA006a5f10.RemoveAll();
  return g_NetworkSessionManager006a5f60.RebuildRuntimeSelectionSource();
}

// FUNCTION: IMPERIALISM 0x005e3a60
unsigned char TNetMgr::OpenRuntimeSelectionSourceByIndexAndCopyPath(int index, int flag,
                                                                    const char* seed) {
  (void)flag;
  strncpy(g_RuntimeSelectionSourceSeedBuffer_006a5fe8, seed, 0x20);
  const GUID* sessionGuid = static_cast<const GUID*>(g_WNetSerializedPtrArrayA006a5f10[index]);
  unsigned char result =
      g_NetworkSessionManager006a5f60.OpenRuntimeSelectionSourceWithOptionalSeed(sessionGuid, 0);
  if (result == 0) {
    HandleError(g_NetworkSessionManager006a5f60.lastErrorCode0c);
  }
  return result;
}

// Real IDirectPlay2::EnumPlayers callback for OpenJoinGameRuntimeSelectionAndStartSession:
// the retail body resolves each enumerated player's role via an unmodeled helper and,
// for the host player, records its DPID; otherwise poses the localized error dialog.
// TODO(class-recovery): the role-resolution helper isn't recovered yet.
static BOOL FAR PASCAL RecordHostPlayerIdDuringEnumeration(DPID dpId, DWORD dwPlayerType,
                                                           LPCDPNAME lpName, DWORD dwFlags,
                                                           LPVOID lpContext) {
  (void)dpId;
  (void)dwPlayerType;
  (void)lpName;
  (void)dwFlags;
  (void)lpContext;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e3c00
unsigned char TNetMgr::ReturnTrueRuntimeCredentialFinalizeStub() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e3c20
unsigned char TNetMgr::OpenJoinGameRuntimeSelectionAndStartSession(int selectionTag,
                                                                   CString* outGameName,
                                                                   const char* seed) {
  strncpy(g_JoinGameSeedBuffer_006a5fc8, seed, 0x20);
  g_JoinGamePlayerNameStaging_006a6008 = *outGameName;

  if (!g_NetworkSessionManager006a5f60.OpenRuntimeSelectionSourceWithUserChoice()) {
    return 0;
  }
  *outGameName = g_JoinGamePlayerNameStaging_006a6008;

  LPSTR shortName = g_JoinGamePlayerNameStaging_006a6008.GetBuffer(1);
  DPID localPlayerId;
  unsigned char createResult =
      g_NetworkSessionManager006a5f60.CreatePlayerAndStoreResult(&localPlayerId, shortName);
  g_JoinGamePlayerNameStaging_006a6008.ReleaseBuffer(-1);
  if (!createResult) {
    return 0;
  }

  g_NetworkDefaultNationId006a5fc0 = localPlayerId;
  if (!g_NetworkSessionManager006a5f60.SetLocalPlayerDataAndStoreResult(
          &g_JoinGamePlayerDataTag_006a600c, sizeof(g_JoinGamePlayerDataTag_006a600c))) {
    return 0;
  }

  g_NetworkBroadcastNationId006a5fc4 = 0;
  long enumResult = g_NetworkSessionManager006a5f60.directPlayInterface04->EnumPlayers(
      0, RecordHostPlayerIdDuringEnumeration, &g_NetworkSessionManager006a5f60, 0x10);
  g_NetworkSessionManager006a5f60.lastErrorCode0c = enumResult;
  if (enumResult < 0) {
    return 0;
  }
  return g_NetworkBroadcastNationId006a5fc4 != 0;
}

// FUNCTION: IMPERIALISM 0x005e3d40
unsigned char TNetMgr::Send(NetMessage* message, unsigned char queueOnly) {
  unsigned int sizeBytes = static_cast<unsigned int>(message->messageLength);
  message->fromNetworkId = g_NetworkDefaultNationId006a5fc0;
  int nationId = message->toNetworkId;
  if (message->toNetworkId == -1) {
    nationId = g_NetworkBroadcastNationId006a5fc4;
  }

  if (queueOnly != 0 || nationId == g_NetworkDefaultNationId006a5fc0) {
    void* heapCopy = GlobalAlloc(0, static_cast<DWORD>(sizeBytes));
    memcpy(heapCopy, message, sizeBytes);
    g_WNetPendingPacketList006a5f40.AddTail(heapCopy);
    if (nationId == g_NetworkDefaultNationId006a5fc0) {
      return 1;
    }
  }

  if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(nationId, message, sizeBytes)) {
    return 1;
  }
  HandleError(g_NetworkSessionManager006a5f60.lastErrorCode0c);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e3ef0
void TNetMgr::ResetTurnEventQueueRuntimeRecordBuffer() {
  g_NetworkSessionManager006a5f60.ResetRuntimeSelectionRecordBuffer();
}

// FUNCTION: IMPERIALISM 0x005e4280
int GetSessionActiveNationId() {
  return g_NetworkDefaultNationId006a5fc0;
}

// Empty session-phase-tag-changed hook (RET 4); invoked when TMultiplayerMgr sets the
// 'init' phase tag.
// FUNCTION: IMPERIALISM 0x005e42a0
void TNetMgr::NoOpDialogModeTagChangedHook(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x005e42c0
void TNetMgr::NotifyIfNationMatchesSessionActiveNation(int nationId) {
  if (nationId == g_NetworkDefaultNationId006a5fc0) {
    g_NetworkSessionManager006a5f60.DestroyPlayerAndStoreResult(nationId);
  }
}

// Event-0x2b reachability probe header: two per-nation bytes reuse the +0x18 area.
struct ReachabilityProbeEvent2BPacket : TimelyMessageHeader {
  unsigned char pendingByte18;  // +0x18 - zeroed
  unsigned char activeNation19; // +0x19
  unsigned char pad1a[2];       // total 0x1c
};

// FUNCTION: IMPERIALISM 0x005e43e0
int TNetMgr::ProbeNationReachabilityAndMarkAwolBitmask() {
  int awolBitmask = 0;
  ReachabilityProbeEvent2BPacket probe;
  probe.messageTag = 0x74696d65;
  probe.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  probe.eventCode = 0;
  probe.fromNetworkId = 0;
  probe.eventCode = 0x2b;
  probe.toNetworkId = 0;
  probe.messageLength = 0;
  probe.messageLength = 0x1c;
  probe.pendingByte18 = 0;
  probe.activeNation19 = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  int slot = 0;
  for (TGreatPower** cell = g_apNationStates; cell < g_apNationStates + 7; ++cell, ++slot) {
    TGreatPower* nation = *cell;
    if (nation != 0 && nation->diplomacyEligibilityA0 != 0 &&
        nation->ShouldDispatchImmediatelySlot28() != 0) {
      if (g_pGameFlowState->nationSessionIds[slot] == -2) {
        awolBitmask += 1 << slot;
      } else {
        probe.DestinateToGP(slot);
        probe.fromNetworkId = g_NetworkDefaultNationId006a5fc0;
        int destination = probe.toNetworkId;
        if (destination == -1) {
          destination = g_NetworkBroadcastNationId006a5fc4;
        }
        if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(destination, &probe,
                                                                 probe.messageLength) == 0) {
          awolBitmask += 1 << slot;
          g_pGameFlowState->SetNationStatusAwolByNationIdAndDispatchNotices(slot);
        }
      }
    }
  }
  return awolBitmask;
}
