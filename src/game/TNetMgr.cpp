#include "game/TNetMgr.h"

#include "game/CString.h"
#include "game/NetMessage.h"
#include "game/TViewMgr.h"
#include "game/TWNetSessionManager.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

#include <cstring>
#include <new>

extern "C" {
char g_pClassDescTNetMgr = 0;
}
IMPLEMENT_DYNCREATE(TNetMgr, TObject)

TNetMgr::TNetMgr() : TObject() {}

// FUNCTION: IMPERIALISM 0x005e33e0
TNetMgr* TNetMgr::ConstructGlobalTurnEventQueueManager(TNetMgr* storage) {
  return new (storage) TNetMgr();
}

TNetMgr::~TNetMgr() {}

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

  g_pUiRuntimeContext->RunControlStringProviderAndDispatchLocalizedMessage(&message);
  if (DAT_006a601c == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
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

// FUNCTION: IMPERIALISM 0x005e4280
int GetSessionActiveNationId() {
  return g_NetworkDefaultNationId006a5fc0;
}

// FUNCTION: IMPERIALISM 0x005e42c0
void __stdcall NotifyIfNationMatchesSessionActiveNation(int nationId) {
  if (nationId == g_NetworkDefaultNationId006a5fc0) {
    g_NetworkSessionManager006a5f60.DestroyPlayerAndStoreResult(nationId);
  }
}
