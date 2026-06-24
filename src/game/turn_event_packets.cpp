#include "game/turn_event_packets.h"

#include "game/CString.h"
#include "game/mfc.h"
#include "game/mfc.h"
#include "game/TMapMgr.h"
#include "game/TTurnEventPacket.h"
#include "game/TViewMgr.h"
#include "game/TWNetSessionManager.h"
#include "game/diplomacy_globals.h"
#include "game/network_error_reporting.h"

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
  this->targetNationId =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGameFlowState) + nationSlot * 4 + 0x48);
}

struct TurnEvent3Mode18Packet {
  TTurnEventPacketRoutingPrefix routing;
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad0b[3];
  int field10;
  int field14;
};

// FUNCTION: IMPERIALISM 0x005446a0
void EmitTurnEvent3Mode18WithActiveNation(void) {
  TurnEvent3Mode18Packet packet;
  packet.routing.eventCode = 0;
  packet.routing.defaultNationId = 0;
  packet.routing.targetNationId = 0;
  packet.routing.payloadSize = 0;
  packet.packetTag = 0;
  packet.activeNationId = 0;
  packet.field10 = 0;
  packet.field14 = 0;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pUiRuntimeContext->GetActiveNationId());
  packet.routing.eventCode = 3;
  packet.routing.payloadSize = 0x18;
  packet.routing.EnqueueOrSendTurnEventPacketToNation(1);
}

#pragma pack(push, 1)
struct CityRedrawInvalidateTurnEventPacket {
  TTurnEventPacketRoutingPrefix routing;
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad0b;
  short uiTurnToken;
  short cityId;
  unsigned char cityHeader00[4];
  short cityWord04;
  short cityWord06;
  unsigned char cityByte08;
  short cityWords0A[12];
  short cityWords22[12];
  unsigned char cityBytes3A[3];
  short cityWord3E;
  short cityWord40;
  short cityWords42[32];
  short cityWords82[10];
  int cityDword98;
  int cityDword9C;
  unsigned char cityBytesA0[4];
  CString cityNameA4;
};
#pragma pack(pop)

// FUNCTION: IMPERIALISM 0x0054abf0
void DispatchCityRedrawInvalidateEvent(short cityId) {
  CityRedrawInvalidateTurnEventPacket packet;
  packet.routing.eventCode = 0x24;
  packet.routing.defaultNationId = 0;
  packet.routing.targetNationId = 0;
  packet.routing.payloadSize = 200;
  packet.packetTag = 0x74696d65;
  packet.activeNationId =
      static_cast<unsigned char>(g_pUiRuntimeContext->GetActiveNationId());
  packet.uiTurnToken =
      *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pGameFlowState) + 0xf0);
  packet.cityId = cityId;

  char* cityRecordBase =
      reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + cityId * 0xa8;
  int cityRecordDelta = static_cast<int>(cityRecordBase - reinterpret_cast<char*>(&packet.cityHeader00));

  packet.cityHeader00[0] = cityRecordBase[0];
  packet.cityHeader00[1] = cityRecordBase[1];
  packet.cityHeader00[2] = cityRecordBase[2];
  packet.cityHeader00[3] = cityRecordBase[3];
  packet.cityWord04 = *reinterpret_cast<short*>(cityRecordBase + 4);
  packet.cityWord06 = *reinterpret_cast<short*>(cityRecordBase + 6);
  packet.cityByte08 = cityRecordBase[8];

  for (int wordIndex0A = 0; wordIndex0A < 12; ++wordIndex0A) {
    packet.cityWords0A[wordIndex0A] =
        *reinterpret_cast<short*>(cityRecordDelta +
                                  reinterpret_cast<int>(packet.cityWords0A + wordIndex0A));
    packet.cityWords22[wordIndex0A] =
        *reinterpret_cast<short*>(cityRecordDelta +
                                  reinterpret_cast<int>(packet.cityWords22 + wordIndex0A));
  }

  packet.cityBytes3A[0] = cityRecordBase[0x3a];
  packet.cityBytes3A[1] = cityRecordBase[0x3b];
  packet.cityBytes3A[2] = cityRecordBase[0x3c];
  packet.cityWord3E = *reinterpret_cast<short*>(cityRecordBase + 0x3e);
  packet.cityWord40 = *reinterpret_cast<short*>(cityRecordBase + 0x40);

  for (int wordIndex42 = 0; wordIndex42 < 32; ++wordIndex42) {
    packet.cityWords42[wordIndex42] =
        *reinterpret_cast<short*>(cityRecordDelta +
                                  reinterpret_cast<int>(packet.cityWords42 + wordIndex42));
  }
  for (int wordIndex82 = 0; wordIndex82 < 10; ++wordIndex82) {
    packet.cityWords82[wordIndex82] =
        *reinterpret_cast<short*>(cityRecordDelta +
                                  reinterpret_cast<int>(packet.cityWords82 + wordIndex82));
  }

  packet.cityDword98 = *reinterpret_cast<int*>(cityRecordBase + 0x98);
  packet.cityDword9C = *reinterpret_cast<int*>(cityRecordBase + 0x9c);
  packet.cityBytesA0[0] = cityRecordBase[0xa0];
  packet.cityBytesA0[1] = cityRecordBase[0xa1];
  packet.cityBytesA0[2] = cityRecordBase[0xa2];
  packet.cityBytesA0[3] = cityRecordBase[0xa3];
  packet.cityNameA4 = *reinterpret_cast<CString*>(cityRecordBase + 0xa4);

  packet.routing.EnqueueOrSendTurnEventPacketToNation(0);
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

  if (g_NetworkSessionManager006a5f60.TrySendNetworkPacket(nationId, this, sizeBytes)) {
    return 1;
  }
  g_NetworkManagerLastError006a5f6c = g_NetworkSessionManager006a5f60.lastErrorCode0c;
  ReportWNetManagerErrorCodeAndNotifyUi(g_NetworkManagerLastError006a5f6c);
  return 0;
}
