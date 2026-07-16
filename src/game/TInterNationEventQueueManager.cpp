#include "game/TNewsMgr.h"

#include "game/global_data_tables.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TPtrList.h"

// Record layout is three dwords — the original 0x55c9f0 compares and stores dwords
// ({int code, int nation, int mask}), same shape as TBilateralActionRelationEntry.
struct TInterNationEventDedupPacket {
  int eventCode0;
  int nationSlot4;
  int nationMask8;
};

// Forward iterator over a TPtrList's 1-based entry array. `owner` is the
// queue being walked; `counter` is the current 1-based index. The three real
// thiscall methods live at 0x5e1fa0/0x5e1fd0/0x5e2000 (previously reached via
// raw-address __fastcall casts through ILT thunks).
struct TPlaybackWalkState {
  int counter;
  TSortedPtrList* owner;

  void* Begin();
  int IsValid();
  void* Next();
};

// FUNCTION: IMPERIALISM 0x0055c970
void TNewsMgr::QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                     char isReplayBypass) {
  if (g_pSimMgr == 0) {
    return;
  }
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass != '\0' || g_pSimMgr->redrawEnabled == 0) {
    TSortedPtrList* interNationQueue = perNationEventBuckets[eventCode];
    if (interNationQueue != 0) {
      interNationQueue->InsertCopiedRecordSortedByComparator(&payloadOrNation);
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
void TNewsMgr::QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
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
      if (packet->nationSlot4 == static_cast<short>(nationA) &&
          (packet->nationMask8 & (1 << (nationB & 0x1f))) != 0) {
        return;
      }
      if (packet->nationSlot4 == static_cast<short>(nationB) &&
          (packet->nationMask8 & (1 << (nationA & 0x1f))) != 0) {
        return;
      }
    }
    packet = static_cast<TInterNationEventDedupPacket*>(playbackState.Next());
  }

  if (nationA < 7) {
    TInterNationEventDedupPacket packetA;
    packetA.eventCode0 = static_cast<short>(eventCode);
    packetA.nationSlot4 = static_cast<short>(nationA);
    packetA.nationMask8 = 1 << (nationB & 0x1f);
    if (sharedEventRecordQueue != 0) {
      sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&packetA);
    }
  }
  if (nationB < 7 && eventCode > 1 && eventCode < 0x19) {
    TInterNationEventDedupPacket packetB;
    packetB.eventCode0 = static_cast<short>(eventCode);
    packetB.nationSlot4 = static_cast<short>(nationB);
    packetB.nationMask8 = 1 << (nationA & 0x1f);
    if (sharedEventRecordQueue != 0) {
      sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&packetB);
    }
  }
}

TSortedPtrList* TNewsMgr::GetInterNationQueueByEventCode(int eventCode) {
  if (eventCode >= 0 && eventCode < 7) {
    return perNationEventBuckets[eventCode];
  }
  if (eventCode == 7) {
    return sharedEventRecordQueue;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055cbd0
void TNewsMgr::QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA, int nationB,
                                                           char isReplayBypass) {
  if (g_pSimMgr == 0) {
    return;
  }
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }

  if (isReplayBypass != '\0' || g_pSimMgr->redrawEnabled == 0) {
    TSortedPtrList* mergeQueue = sharedEventRecordQueue;
    if (mergeQueue == 0) {
      return;
    }

    int queueCount = mergeQueue->GetSize();
    int entryIndex = 1;
    if (entryIndex <= queueCount) {
      do {
        TInterNationEventType0FMergePayload* existingEntry =
            reinterpret_cast<TInterNationEventType0FMergePayload*>(
                mergeQueue->GetPtrListEntryByOneBasedIndex(entryIndex));
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
    mergeQueue->InsertCopiedRecordSortedByComparator(reinterpret_cast<int*>(&payload));
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

// FUNCTION: IMPERIALISM 0x0055cd00
void TNewsMgr::QueueInterNationEventType11(int eventParam, int value, char isReplayBypass) {
  if (g_pSimMgr->gateFlag7a == 0) {
    if (isReplayBypass == 0) {
      unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
      if (multiplayerActive != 0) {
        g_pGameFlowState->CreateAndSendTurnEvent22_ByteAndShort((unsigned char)eventParam,
                                                                (short)value);
        return;
      }
    }
    // Frame evidence (sub esp,0x10): the stack record reserves four dwords even though
    // only the first three are written -- same shape as the other queue records.
    int record[4];
    record[2] = value;
    record[1] = eventParam;
    record[0] = 0x11;
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(record);
  }
}

// FUNCTION: IMPERIALISM 0x0055cda0
void TNewsMgr::AddOrUpdateBilateralActionRelationEntry(int eventCode, int nationA, int nationB) {
  bool nationAHandled = 6 < nationA;
  bool nationBHandled = 6 < nationB;
  if (((6 < eventCode && eventCode < 0xe)) || eventCode == 0x12 || eventCode == 0x14) {
    nationBHandled = true;
  }
  int entryIndex = 1;
  while (!(nationAHandled && nationBHandled) && entryIndex <= sharedEventRecordQueue->GetSize()) {
    TBilateralActionRelationEntry* entry = static_cast<TBilateralActionRelationEntry*>(
        sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(entryIndex));
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
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&newEntryA.eventCode0);
  }
  if (!nationBHandled) {
    TBilateralActionRelationEntry newEntryB;
    newEntryB.eventCode0 = eventCode;
    newEntryB.nationSlot4 = nationB;
    newEntryB.nationMask8 = 1 << (nationA & 0x1f);
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&newEntryB.eventCode0);
  }
}

// FUNCTION: IMPERIALISM 0x005e1fa0
void* TPlaybackWalkState::Begin() {
  counter = 2;
  return owner->GetPtrListEntryByOneBasedIndex(1);
}

// FUNCTION: IMPERIALISM 0x005e1fd0
int TPlaybackWalkState::IsValid() {
  return counter <= owner->GetSize() ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x005e2000
void* TPlaybackWalkState::Next() {
  int index = counter;
  counter = index + 1;
  return owner->GetPtrListEntryByOneBasedIndex(index);
}
