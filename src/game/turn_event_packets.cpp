#include "game/turn_event_packets.h"

#include "game/CPlex.h"
#include "game/CPtrList.h"
#include "game/TTurnEventPacket.h"
#include "game/TWNetSessionManager.h"
#include "game/UiRuntimeContext.h"
#include "game/diplomacy_globals.h"
#include "game/network_error_reporting.h"

#include <windows.h>

extern "C" {
extern int g_NetworkDefaultNationId006a5fc0;
extern int g_NetworkBroadcastNationId006a5fc4;
extern void* g_pNetworkPacketQueueHead006a5f50;
extern void* g_pNetworkPacketQueueTail006a5f48;
extern void* g_pNetworkPacketQueueRoot006a5f44;
extern int g_NetworkPacketQueueCount006a5f4c;
extern int g_NetworkPacketBlockCount006a5f58;
extern void* g_pNetworkPacketBlockChain006a5f54;
extern int g_NetworkManagerLastError006a5f6c;
}

// FUNCTION: IMPERIALISM 0x005420a0
void TTurnEventPacketRoutingPrefix::SetPayloadNationIdFromSlotIndex(int nationSlot) {
  this->targetNationId = *reinterpret_cast<int*>(
      reinterpret_cast<char*>(g_pGameFlowState) + nationSlot * 4 + 0x48);
}

// FUNCTION: IMPERIALISM 0x0054c5a0
void DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation, int mode) {
  TJoinEmpireTurnEventPacket packet;
  packet.routing.eventCode = 0x27;
  packet.routing.payloadSize = 0x24;
  packet.packetTag = 0x74696D65;
  packet.activeNationId = static_cast<unsigned char>(g_pUiRuntimeContext->GetActiveNationId());
  packet.sourceNationSlot = sourceNation;
  packet.targetNationSlot = targetNation;
  packet.modeValue = mode;
  packet.routing.EnqueueOrSendTurnEventPacketToNation(0);
}

// FUNCTION: IMPERIALISM 0x005e3d40
undefined4 TTurnEventPacketRoutingPrefix::EnqueueOrSendTurnEventPacketToNation(char queueOnly) {
  unsigned int sizeBytes = static_cast<unsigned int>(this->payloadSize);
  this->defaultNationId = g_NetworkDefaultNationId006a5fc0;
  int nationId = this->targetNationId;
  if (this->targetNationId == -1) {
    nationId = g_NetworkBroadcastNationId006a5fc4;
  }

  if (queueOnly != 0 || nationId == g_NetworkDefaultNationId006a5fc0) {
    undefined4* heapCopy =
        reinterpret_cast<undefined4*>(GlobalAlloc(0, static_cast<DWORD>(sizeBytes)));
    undefined4* src = reinterpret_cast<undefined4*>(this);
    undefined4* dst = heapCopy;
    unsigned int dwordCount = sizeBytes >> 2;
    while (dwordCount != 0) {
      *dst = *src;
      src = src + 1;
      dst = dst + 1;
      dwordCount = dwordCount - 1;
    }
    unsigned int tailBytes = sizeBytes & 3;
    while (tailBytes != 0) {
      *reinterpret_cast<unsigned char*>(dst) = *reinterpret_cast<unsigned char*>(src);
      src = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(src) + 1);
      dst = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(dst) + 1);
      tailBytes = tailBytes - 1;
    }

    undefined4* queueNode = reinterpret_cast<undefined4*>(g_pNetworkPacketQueueHead006a5f50);
    if (g_pNetworkPacketQueueHead006a5f50 == 0) {
      CPlex*& chain = *reinterpret_cast<CPlex**>(&g_pNetworkPacketBlockChain006a5f54);
      CPlex* block = CPlex::Create(chain, static_cast<unsigned int>(g_NetworkPacketBlockCount006a5f58), 0xc);
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

  if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(nationId, this, sizeBytes)) {
    return 1;
  }
  g_NetworkManagerLastError006a5f6c = g_NetworkSessionManager006a5f60.lastErrorCode0c;
  ReportWNetManagerErrorCodeAndNotifyUi(g_NetworkManagerLastError006a5f6c);
  return 0;
}
