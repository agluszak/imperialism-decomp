#include "game/TInterNationEventQueueManager.h"

#include "game/diplomacy_globals.h"
#include "game/TLocalizationRuntime.h"
#include "game/TQueueObject.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 thunk_CreateAndSendTurnEvent13_NationAndNineDwords(void);
undefined4 thunk_CreateAndSendTurnEvent21_ThreeBytes(void);

struct TInterNationEventDedupPacket {
  short eventCode0;
  short nationSlot2;
  int nationMask4;
};

struct TPlaybackWalkState {
  int counter;
  TQueueObject* owner;
};

// FUNCTION: IMPERIALISM 0x00406758
void TInterNationEventQueueManager::thunk_QueueInterNationEventRecordDeduped(
    int eventCode, int nationA, int nationB, char isReplayBypass) {
  QueueInterNationEventRecordDeduped(eventCode, nationA, nationB, isReplayBypass);
}

// FUNCTION: IMPERIALISM 0x0055c9f0
void TInterNationEventQueueManager::QueueInterNationEventRecordDeduped(int eventCode, int nationA,
                                                                       int nationB,
                                                                       char isReplayBypass) {
  if (g_pLocalizationTable == 0) {
    return;
  }
  if (g_pLocalizationTable->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass == 0 && g_pLocalizationTable->redrawEnabled != 0) {
    if (g_pLocalizationTable->redrawEnabled == 1) {
      reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(0x00405bd7)(g_pGameFlowState,
                                                                              eventCode, nationA,
                                                                              nationB);
      return;
    }
    return;
  }

  if (eventCode >= 5 && eventCode <= 0x15) {
    reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(0x00406bf9)(this, eventCode, nationA,
                                                                          nationB);
    return;
  }

  TPlaybackWalkState playbackState;
  playbackState.owner = sharedEventRecordQueue;

  TInterNationEventDedupPacket* packet = reinterpret_cast<TInterNationEventDedupPacket*>(
      reinterpret_cast<int*(__fastcall*)(TPlaybackWalkState*)>(0x00407919)(&playbackState));
  while (reinterpret_cast<int(__fastcall*)(TPlaybackWalkState*)>(0x00409679)(&playbackState) != 0) {
    if (packet->eventCode0 == static_cast<short>(eventCode)) {
      if (packet->nationSlot2 == static_cast<short>(nationA) &&
          (packet->nationMask4 & (1 << (nationB & 0x1f))) != 0) {
        return;
      }
      if (packet->nationSlot2 == static_cast<short>(nationB) &&
          (packet->nationMask4 & (1 << (nationA & 0x1f))) != 0) {
        return;
      }
    }
    packet = reinterpret_cast<TInterNationEventDedupPacket*>(
        reinterpret_cast<int*(__fastcall*)(TPlaybackWalkState*)>(0x004097dc)(&playbackState));
  }

  if (nationA < 7) {
    TInterNationEventDedupPacket packetA;
    packetA.eventCode0 = static_cast<short>(eventCode);
    packetA.nationSlot2 = static_cast<short>(nationA);
    packetA.nationMask4 = 1 << (nationB & 0x1f);
    if (sharedEventRecordQueue != 0) {
      sharedEventRecordQueue->AddEntrySlot38(reinterpret_cast<int*>(&packetA));
    }
  }
  if (nationB < 7 && eventCode > 1 && eventCode < 0x19) {
    TInterNationEventDedupPacket packetB;
    packetB.eventCode0 = static_cast<short>(eventCode);
    packetB.nationSlot2 = static_cast<short>(nationB);
    packetB.nationMask4 = 1 << (nationA & 0x1f);
    if (sharedEventRecordQueue != 0) {
      sharedEventRecordQueue->AddEntrySlot38(reinterpret_cast<int*>(&packetB));
    }
  }
}

TQueueObject* TInterNationEventQueueManager::GetInterNationQueueByEventCode(int eventCode) {
  if (eventCode >= 0 && eventCode < 7) {
    return perNationEventBuckets[eventCode];
  }
  if (eventCode == 7) {
    return sharedEventRecordQueue;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055c970
void TInterNationEventQueueManager::QueueInterNationEventIntoNationBucket(int eventCode,
                                                                          int payloadOrNation,
                                                                          char isReplayBypass) {
  if (g_pLocalizationTable == 0) {
    return;
  }
  if (g_pLocalizationTable->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass != '\0' || g_pLocalizationTable->redrawEnabled == 0) {
    TQueueObject* interNationQueue = perNationEventBuckets[eventCode];
    if (interNationQueue != 0) {
      interNationQueue->AddEntrySlot38(&payloadOrNation);
    }
    return;
  }

  reinterpret_cast<void(__cdecl*)(int, int)>(thunk_CreateAndSendTurnEvent13_NationAndNineDwords)(
      eventCode, payloadOrNation);
}

struct TInterNationEventType0FMergePayload {
  int eventMarker0;
  int eventCode4;
  int nationMask8;
  int nationB12;
};

// FUNCTION: IMPERIALISM 0x0055cbd0
void TInterNationEventQueueManager::QueueInterNationEventType0FWithBitmaskMerge(int eventCode,
                                                                                int nationA,
                                                                                int nationB,
                                                                                char isReplayBypass) {
  if (g_pLocalizationTable == 0) {
    return;
  }
  if (g_pLocalizationTable->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass != '\0' || g_pLocalizationTable->redrawEnabled == 0) {
    TQueueObject* mergeQueue = sharedEventRecordQueue;
    if (mergeQueue == 0) {
      return;
    }

    int queueCount = mergeQueue->GetEntryCount();
    int entryIndex = 1;
    if (entryIndex <= queueCount) {
      do {
        TInterNationEventType0FMergePayload* existingEntry =
            reinterpret_cast<TInterNationEventType0FMergePayload*>(
                mergeQueue->GetEntryAt1BasedSlot2C(entryIndex));
        if (existingEntry != 0 && existingEntry->eventMarker0 == 0x0F &&
            existingEntry->nationB12 == nationB && existingEntry->eventCode4 == eventCode) {
          existingEntry->nationMask8 |= 1 << (nationA & 0x1f);
          return;
        }
        ++entryIndex;
      } while (entryIndex <= queueCount);
    }

    TInterNationEventType0FMergePayload payload;
    payload.eventMarker0 = 0x0F;
    payload.eventCode4 = eventCode;
    payload.nationMask8 = 1 << (nationA & 0x1f);
    payload.nationB12 = nationB;
    mergeQueue->AddEntrySlot38(reinterpret_cast<int*>(&payload));
    return;
  }

  reinterpret_cast<void(__cdecl*)(void)>(thunk_CreateAndSendTurnEvent21_ThreeBytes)();
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
