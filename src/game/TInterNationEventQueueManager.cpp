#include "game/TInterNationEventQueueManager.h"

#include "game/global_data_tables.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TQueueObject.h"

struct TInterNationEventDedupPacket {
  short eventCode0;
  short nationSlot2;
  int nationMask4;
};

// Forward iterator over a TQueueObject's 1-based entry array. `owner` is the
// queue being walked; `counter` is the current 1-based index. The three real
// thiscall methods live at 0x5e1fa0/0x5e1fd0/0x5e2000 (previously reached via
// raw-address __fastcall casts through ILT thunks).
struct TPlaybackWalkState {
  int counter;
  TQueueObject* owner;

  void* Begin();
  int IsValid();
  void* Next();
};

// FUNCTION: IMPERIALISM 0x0055c970
void TInterNationEventQueueManager::QueueInterNationEventIntoNationBucket(int eventCode,
                                                                          int payloadOrNation,
                                                                          char isReplayBypass) {
  if (g_pSimMgr == 0) {
    return;
  }
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass != '\0' || g_pSimMgr->redrawEnabled == 0) {
    TQueueObject* interNationQueue = perNationEventBuckets[eventCode];
    if (interNationQueue != 0) {
      interNationQueue->AddEntrySlot38(&payloadOrNation);
    }
    return;
  }

  g_pGameFlowState->CreateAndSendTurnEvent13_NationAndNineDwords(
      eventCode, reinterpret_cast<int*>(payloadOrNation));
}

struct TInterNationEventType0FMergePayload {
  int eventMarker0;
  int eventCode4;
  int nationMask8;
  int nationB12;
};

// FUNCTION: IMPERIALISM 0x0055c9f0
void TInterNationEventQueueManager::QueueInterNationEventRecordDeduped(int eventCode, int nationA,
                                                                       int nationB,
                                                                       char isReplayBypass) {
  if (g_pSimMgr == 0) {
    return;
  }
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass == 0 && g_pSimMgr->redrawEnabled != 0) {
    if (g_pSimMgr->redrawEnabled == 1) {
      g_pGameFlowState->CreateAndSendTurnEvent20_ShortAndTwoBytes(
          static_cast<short>(eventCode), static_cast<unsigned char>(nationA),
          static_cast<unsigned char>(nationB));
      return;
    }
    return;
  }

  if (eventCode >= 5 && eventCode <= 0x15) {
    AddOrUpdateBilateralActionRelationEntry(eventCode, nationA, nationB);
    return;
  }

  TPlaybackWalkState playbackState;
  playbackState.owner = sharedEventRecordQueue;

  TInterNationEventDedupPacket* packet =
      static_cast<TInterNationEventDedupPacket*>(playbackState.Begin());
  while (playbackState.IsValid() != 0) {
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
    packet = static_cast<TInterNationEventDedupPacket*>(playbackState.Next());
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

// FUNCTION: IMPERIALISM 0x0055cbd0
void TInterNationEventQueueManager::QueueInterNationEventType0FWithBitmaskMerge(
    int eventCode, int nationA, int nationB, char isReplayBypass) {
  if (g_pSimMgr == 0) {
    return;
  }
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass != '\0' || g_pSimMgr->redrawEnabled == 0) {
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

  g_pGameFlowState->CreateAndSendTurnEvent21_ThreeBytes(static_cast<unsigned char>(eventCode),
                                                        static_cast<unsigned char>(nationA),
                                                        static_cast<unsigned char>(nationB));
}

// Per-nation-pair relation record kept in sharedEventRecordQueue by
// AddOrUpdateBilateralActionRelationEntry (12-byte {eventCode, nationSlot, nationMask}
// rows — a different record shape than TInterNationEventDedupPacket).
struct TBilateralActionRelationEntry {
  int eventCode0;
  int nationSlot4;
  int nationMask8;
};

// FUNCTION: IMPERIALISM 0x0055cda0
void TInterNationEventQueueManager::AddOrUpdateBilateralActionRelationEntry(int eventCode,
                                                                            int nationA,
                                                                            int nationB) {
  bool nationAHandled = 6 < nationA;
  bool nationBHandled = 6 < nationB;
  if (((6 < eventCode && eventCode < 0xe)) || eventCode == 0x12 || eventCode == 0x14) {
    nationBHandled = true;
  }
  int entryIndex = 1;
  while (!(nationAHandled && nationBHandled) &&
         entryIndex <= sharedEventRecordQueue->GetEntryCount()) {
    TBilateralActionRelationEntry* entry = static_cast<TBilateralActionRelationEntry*>(
        sharedEventRecordQueue->GetEntryAt1BasedSlot2C(entryIndex));
    if (entry->eventCode0 == eventCode) {
      if (!nationAHandled && entry->nationSlot4 == nationA) {
        nationAHandled = true;
        entry->nationMask8 = entry->nationMask8 | (1 << (nationB & 0x1f));
      }
      if (!nationBHandled && entry->nationSlot4 == nationB) {
        nationBHandled = true;
        entry->nationMask8 = entry->nationMask8 | (1 << (nationA & 0x1f));
      }
    }
    entryIndex = entryIndex + 1;
  }
  if (!nationAHandled) {
    TBilateralActionRelationEntry newEntryA;
    newEntryA.eventCode0 = eventCode;
    newEntryA.nationSlot4 = nationA;
    newEntryA.nationMask8 = 1 << (nationB & 0x1f);
    sharedEventRecordQueue->AddEntrySlot38(&newEntryA.eventCode0);
  }
  if (!nationBHandled) {
    TBilateralActionRelationEntry newEntryB;
    newEntryB.eventCode0 = eventCode;
    newEntryB.nationSlot4 = nationB;
    newEntryB.nationMask8 = 1 << (nationA & 0x1f);
    sharedEventRecordQueue->AddEntrySlot38(&newEntryB.eventCode0);
  }
}

// FUNCTION: IMPERIALISM 0x005e1fa0
void* TPlaybackWalkState::Begin() {
  counter = 2;
  return owner->GetEntrySlot2C(1);
}

// FUNCTION: IMPERIALISM 0x005e1fd0
int TPlaybackWalkState::IsValid() {
  return counter <= owner->GetEntryCount() ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x005e2000
void* TPlaybackWalkState::Next() {
  int index = counter;
  counter = index + 1;
  return owner->GetEntrySlot2C(index);
}
