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

static const char* LookupDirectPlayErrorDetailText(int errorCode) {
  if (errorCode < -0x7ff8fff1) {
    if (errorCode == -0x7ff8fff2) {
      return "Not enough memory available.";
    }
    if (errorCode == -0x7fffbfff) {
      return "This function is not supported on this system.";
    }
    if (errorCode == -0x7fffbffe) {
      return "No such interface supported.";
    }
    if (errorCode == -0x7fffbffb) {
      return "An undefined error code was returned from a DirectPlay function.";
    }
    return 0;
  }
  if (errorCode < -0x7788fffa) {
    if (errorCode == -0x7788fffb) {
      return "This object is already initialized.";
    }
    if (errorCode == -0x7ff8ffa9) {
      return "One or more parameters were invalid.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffeb) {
    if (errorCode == -0x7788ffec) {
      return "There are active players in the session.";
    }
    if (errorCode == -0x7788fff6) {
      return "Access to the object is denied.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffd7) {
    if (errorCode == -0x7788ffd8) {
      return "Can't add player.";
    }
    if (errorCode == -0x7788ffe2) {
      return "The buffer supplied is too small.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffc3) {
    if (errorCode == -0x7788ffc4) {
      return "Can't create player.";
    }
    if (errorCode == -0x7788ffce) {
      return "Can't create group.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffaf) {
    if (errorCode == -0x7788ffb0) {
      return "The capabilities requested are not yet available.";
    }
    if (errorCode == -0x7788ffba) {
      return "Can't create session.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff87) {
    if (errorCode == -0x7788ff88) {
      return "Invalid flags were specified.";
    }
    if (errorCode == -0x7788ffa6) {
      return "An exception occurred.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff69) {
    if (errorCode == -0x7788ff6a) {
      return "Invalid player.";
    }
    if (errorCode == -0x7788ff7e) {
      return "Invalid object.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff55) {
    if (errorCode == -0x7788ff56) {
      return "No connection.";
    }
    if (errorCode == -0x7788ff60) {
      return "The required capabilities are not available.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff37) {
    if (errorCode == -0x7788ff38) {
      return "No name server found.";
    }
    if (errorCode == -0x7788ff42) {
      return "There are no messages waiting.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff23) {
    if (errorCode == -0x7788ff24) {
      return "There are no sessions available.";
    }
    if (errorCode == -0x7788ff2e) {
      return "There are no players available.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff0f) {
    if (errorCode == -0x7788ff10) {
      return "The operation timed out.";
    }
    if (errorCode == -0x7788ff1a) {
      return "The message is too large to send.";
    }
    return 0;
  }
  if (errorCode < -0x7788fef1) {
    if (errorCode == -0x7788fef2) {
      return "The message queue is full.";
    }
    if (errorCode == -0x7788ff06) {
      return "The service is unavailable.";
    }
    return 0;
  }
  if (errorCode < -0x7788fedd) {
    if (errorCode == -0x7788fede) {
      return "Can't create server.";
    }
    if (errorCode == -0x7788fee8) {
      return "The user canceled the operation.";
    }
    return 0;
  }
  if (errorCode < -0x7788fec9) {
    if (errorCode == -0x7788feca) {
      return "The session was lost.";
    }
    if (errorCode == -0x7788fed4) {
      return "The player was lost.";
    }
    return 0;
  }
  if (errorCode < -0x7788fc0d) {
    if (errorCode == -0x7788fc0e) {
      return "Can't create process.";
    }
    if (errorCode == -0x7788fc18) {
      return "The buffer is too large.";
    }
    return 0;
  }
  if (errorCode < -0x7788fbf9) {
    if (errorCode == -0x7788fbfa) {
      return "Invalid interface.";
    }
    if (errorCode == -0x7788fc04) {
      return "The application is not started.";
    }
    return 0;
  }
  if (errorCode < -0x7788fbe5) {
    if (errorCode == -0x7788fbe6) {
      return "Unknown application.";
    }
    if (errorCode == -0x7788fbf0) {
      return "No service provider available.";
    }
    return 0;
  }
  if (errorCode == -0x7788fbd2) {
    return "Not lobbied.";
  }
  if (errorCode == 0) {
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

    undefined4* queueNode = reinterpret_cast<undefined4*>(g_pNetworkPacketQueueHead006a5f50);
    if (g_pNetworkPacketQueueHead006a5f50 == 0) {
      CPlex*& chain = *reinterpret_cast<CPlex**>(&g_pNetworkPacketBlockChain006a5f54);
      CPlex* block =
          CPlex::Create(chain, static_cast<unsigned int>(g_NetworkPacketBlockCount006a5f58), 0xc);
      int blockBase = reinterpret_cast<int>(block);
      queueNode = reinterpret_cast<undefined4*>(g_pNetworkPacketQueueHead006a5f50);
      undefined4* freeListNode =
          reinterpret_cast<undefined4*>(blockBase + -8 + g_NetworkPacketBlockCount006a5f58 * 0xc);
      int remaining = g_NetworkPacketBlockCount006a5f58;
      if (-1 < g_NetworkPacketBlockCount006a5f58 + -1) {
        do {
          queueNode = freeListNode;
          *queueNode = reinterpret_cast<undefined4>(g_pNetworkPacketQueueHead006a5f50);
          remaining = remaining + -1;
          g_pNetworkPacketQueueHead006a5f50 = queueNode;
          freeListNode = queueNode + -3;
        } while (remaining != 0);
      }
    }
    g_pNetworkPacketQueueHead006a5f50 = *reinterpret_cast<void**>(queueNode);

    queueNode[1] = reinterpret_cast<undefined4>(g_pNetworkPacketQueueTail006a5f48);
    queueNode[0] = 0;
    g_NetworkPacketQueueCount006a5f4c = g_NetworkPacketQueueCount006a5f4c + 1;
    queueNode[2] = 0;
    queueNode[2] = reinterpret_cast<undefined4>(heapCopy);

    undefined4* queueRoot = queueNode;
    if (g_pNetworkPacketQueueTail006a5f48 != 0) {
      *reinterpret_cast<undefined4**>(g_pNetworkPacketQueueTail006a5f48) = queueNode;
      queueRoot = reinterpret_cast<undefined4*>(g_pNetworkPacketQueueRoot006a5f44);
    }
    g_pNetworkPacketQueueRoot006a5f44 = queueRoot;
    g_pNetworkPacketQueueTail006a5f48 = queueNode;
    if (nationId == g_NetworkDefaultNationId006a5fc0) {
      return 1;
    }
  }

  if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(nationId, message, sizeBytes)) {
    return 1;
  }
  g_NetworkManagerLastError006a5f6c = g_NetworkSessionManager006a5f60.lastErrorCode0c;
  HandleError(g_NetworkManagerLastError006a5f6c);
  return 0;
}

undefined TNetMgr::SerializeLinkedRecordListWithFreeNodePool(CArchive* param_1) {
  (void)param_1;
  return 0;
}

undefined TNetMgr::SerializeDynamicDwordPointerArrayState(CArchive* param_1) {
  (void)param_1;
  return 0;
}

undefined TNetMgr::WrapperFor_FreeHeapBufferIfNotNull_At005e4a30(byte param_1) {
  (void)param_1;
  return 0;
}

undefined TNetMgr::WrapperFor_FreeHeapBufferIfNotNull_At005e4a60(byte param_1) {
  (void)param_1;
  return 0;
}
