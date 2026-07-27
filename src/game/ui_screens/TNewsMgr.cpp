#include "game/ui_screens/TNewsMgr.h"

#include "game/military/TArmyMgr.h"
#include "game/assets/TAssetMgr.h"
#include "game/assets/CPtrIterator.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/ui_screens/TZone.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

#include <string.h>

namespace {

static __inline unsigned int ByteSwapNewsTableDword(unsigned int value) {
  return ((value & 0x000000ffU) << 24) | ((value & 0x0000ff00U) << 8) |
         ((value & 0x00ff0000U) >> 8) | ((value & 0xff000000U) >> 24);
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x0055b670
// TNewsMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055b6a0
// TNewsMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0055b6d0
TNewsMgr::~TNewsMgr() {}

// SYNTHETIC: IMPERIALISM 0x0055b6f0
// TNewsMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewsMgr, TObject)

// FUNCTION: IMPERIALISM 0x0055b710
void TNewsMgr::InitializeNewsManager() {
  for (int i = 0; i < 7; i++) {
    perNationEventBuckets[i] = new TSortedPtrList();
    perNationEventBuckets[i]->recordSize14 = 0x24;
    perNationStoryLastUsedTick[i] = 0;
  }
  storyTemplateCount = 0;
  sharedEventRecordQueue = new TSortedPtrList();
  sharedEventRecordQueue->recordSize14 = 0x10;
}

// FUNCTION: IMPERIALISM 0x0055b820
void TNewsMgr::Free() {
  for (int n = 0; n < 7; n++) {
    if (perNationEventBuckets[n] != 0) {
      perNationEventBuckets[n]->ReleasePtrList();
    }
    if (perNationStoryLastUsedTick[n] != 0) {
      delete[] perNationStoryLastUsedTick[n];
    }
  }
  if (sharedEventRecordQueue != 0) {
    sharedEventRecordQueue->ReleasePtrList();
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x0055b8a0
void TNewsMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x0055b8c0
void TNewsMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// News phase (turn machine case 0xf, Mac: StartNewsPhase): load the story-template
// table, lazily allocate the per-nation last-used-tick arrays, build each eligible
// nation's newspaper page, then free the transient table and drop the consumed
// event records.
// FUNCTION: IMPERIALISM 0x0055b8e0
void TNewsMgr::StartNewsPhase() {
  LoadNewsTable();
  if (perNationStoryLastUsedTick[0] == 0) {
    for (int n = 0; n < 7; n++) {
      perNationStoryLastUsedTick[n] = new short[storyTemplateCount];
      for (int i = 0; i < storyTemplateCount; i++) {
        perNationStoryLastUsedTick[n][i] = 0;
      }
    }
  }
  newsTexStream = g_pUiViewManager->LoadTableResourceStreamByName(g_pLanguageMgr->GetNewsTexPath());
  memset(stories, 0, sizeof(stories));
  short slot = 0;
  for (TGreatPower** nation = g_apNationStates; nation < &g_apNationStates_End; ++nation, ++slot) {
    if ((*nation != 0 && (*nation)->diplomacyEligibilityA0 != 0) ||
        g_pSimMgr->GetActiveNationId() == slot) {
      CreateNewspaper(slot);
    }
  }
  delete[] storyTemplateTable;
  g_pUiViewManager->ReleaseResourceStreamIfNotNull(newsTexStream);
  sharedEventRecordQueue->InvokePtrListResetHook();
}

// FUNCTION: IMPERIALISM 0x0055ba30
void TNewsMgr::LoadNewsTable() {
  CFile* stream = g_pUiViewManager->LoadTableResourceStreamByName(g_pLanguageMgr->GetNewsTabPath());
  int byteCount = g_pUiViewManager->GetResourceStreamSize(stream);
  storyTemplateCount = static_cast<unsigned int>(byteCount) / sizeof(newsEntry);
  storyTemplateTable = new newsEntry[storyTemplateCount];
  if (storyTemplateTable == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUNewspaper_00698470, 0x106);
  }
  g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, storyTemplateTable, &byteCount);
  g_pUiViewManager->ReleaseResourceStreamIfNotNull(stream);
  // news.tab is big-endian Mac data: byteswap every field of every record.
  for (int i = 0; i < storyTemplateCount; i++) {
    newsEntry& entry = storyTemplateTable[i];
    entry.storyId = ByteSwapNewsTableDword(entry.storyId);
    entry.headlineTextOffset = ByteSwapNewsTableDword(entry.headlineTextOffset);
    entry.headlineTextLength = ByteSwapNewsTableDword(entry.headlineTextLength);
    entry.storyTextOffset = ByteSwapNewsTableDword(entry.storyTextOffset);
    entry.storyTextLength = ByteSwapNewsTableDword(entry.storyTextLength);
    entry.reserved14 = ByteSwapNewsTableDword(entry.reserved14);
  }
}

// Builds one nation's 3x3 newspaper page: event stories first (CreateEventStories),
// then least-recently-used random filler/feature stories until the page is full or
// four picks in a row failed.
// FUNCTION: IMPERIALISM 0x0055bc10
void TNewsMgr::CreateNewspaper(int nation) {
  int major = 0;
  int minor = 0;
  for (int a = 0; a < 3; a++) {
    for (int b = 0; b < 3; b++) {
      stories[nation][a][b].entry.storyId = 0;
    }
  }
  CreateEventStories(nation, &major, &minor);

  perNationEventBuckets[nation]->InvokePtrListResetHook();
  short* ticks = perNationStoryLastUsedTick[nation];
  short* order = new short[storyTemplateCount];
  int i;
  for (i = 0; i < storyTemplateCount; i++) {
    order[i] = static_cast<short>(i);
  }
  // Selection sort ascending by last-used tick (least recently used first).
  for (i = 0; i < storyTemplateCount - 1; i++) {
    for (int j = i; j < storyTemplateCount; j++) {
      if (ticks[order[j]] < ticks[order[i]]) {
        short t = order[j];
        order[j] = order[i];
        order[i] = t;
      }
    }
  }

  int misses = 0;
  int curTick = g_pSimMgr->GetEconomicTurn();
  while (major < 3 && misses < 4) {
    // Random pick biased toward least-recently-used templates (min of two uniforms
    // over the sorted order), skipping event-story rows (negative ids).
    int pick;
    do {
      int r1 = rand() % storyTemplateCount;
      int r2 = rand() % storyTemplateCount;
      if (r2 <= r1) {
        r1 = r2;
      }
      pick = order[r1];
    } while (storyTemplateTable[pick].storyId < 0);
    if (static_cast<int>(ticks[pick]) == curTick) {
      misses++;
      continue;
    }
    newsEntry* tmpl = &storyTemplateTable[pick];
    newsStory* story = &stories[nation][minor][major];
    int id = tmpl->storyId;
    if (id > 9 && id % 10 == 0) {
      // Decade feature: visible only while the year index is inside [id-10, id).
      short year = static_cast<short>(g_pSimMgr->economicTurn / 4);
      if (year < id - 10 || year >= id) {
        continue;
      }
    } else if (id != 1) {
      continue;
    }
    story->parmKind[0] = 0;
    story->parmKind[1] = 0;
    story->parmKind[2] = 0;
    story->parmKind[3] = 0;
    story->entry = *tmpl;
    story->parmKind[0] = 1;
    story->feature38 = 1;
    story->parmValue[0] = 1 << nation;
    short other;
    do {
      other = static_cast<short>(rand() % 7);
    } while (other == static_cast<short>(nation) || g_apTerrainTypeDescriptorTable[other] == 0);
    story->parmKind[1] = 1;
    story->parmValue[1] = 1 << other;
    ticks[pick] = static_cast<short>(curTick);
    minor++;
    if (minor == 3) {
      minor = 0;
      major++;
    }
    misses = 0;
  }
  delete[] order;
}

// Fills event stories for one nation from the shared discriminated event-record queue,
// advancing the (major, minor) page cursors.
// FUNCTION: IMPERIALISM 0x0055c010
void TNewsMgr::CreateEventStories(int nation, int* majorCursor, int* minorCursor) {
  int ordinal = 0;
  int code = 0;
  InterNationNewsRecord* rec;
  newsEntry* tmpl;
  int t;

  // Phase 1: this-nation bilateral stories, codes 0..0x18, skipping 0xe..0x11.
  do {
    if (*majorCursor > 2) {
      break;
    }
    if (code <= 0xd || code >= 0x12) {
      rec = 0;
      for (int i = ordinal + 1; i <= sharedEventRecordQueue->GetSize(); i++) {
        InterNationNewsRecord* entry = static_cast<InterNationNewsRecord*>(
            sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(i));
        if (entry->eventKind == code && entry->payload.treaty.subjectNation == nation) {
          rec = entry;
          ordinal = i;
          break;
        }
      }
      if (rec == 0) {
        ordinal = 0;
        code++;
      } else {
        newsStory* story = &stories[nation][*minorCursor][*majorCursor];
        story->feature38 = 0;
        story->parmKind[0] = 1;
        story->parmValue[0] = 1 << rec->payload.treaty.subjectNation;
        story->parmValue[1] = rec->payload.treaty.counterpartNationMask;
        story->parmKind[1] = 1;
        for (int k = 2; k < 4; k++) {
          story->parmValue[k] = 0;
          story->parmKind[k] = 0;
        }
        int wantId = -100 - rec->eventKind;
        if (rec->eventKind >= kInterNationEventNonAggressionPactAccepted &&
            rec->eventKind <= 0x15) {
          short bits = 0;
          for (int b = 0; b < 0x17; b++) {
            if (rec->payload.treaty.counterpartNationMask & (1 << b)) {
              bits++;
            }
          }
          if (bits > 1) {
            wantId = -0x65 - rec->eventKind;
          }
        }
        tmpl = storyTemplateTable;
        for (t = 0; t < storyTemplateCount; t++, tmpl++) {
          if (tmpl->storyId == wantId) {
            break;
          }
        }
        if (t < storyTemplateCount) {
          story->entry = *tmpl;
          ++*minorCursor;
          if (*minorCursor == 3) {
            *minorCursor = 0;
            ++*majorCursor;
          }
        }
      }
    } else {
      code++;
    }
  } while (code <= 0x18);

  if (*majorCursor >= 3) {
    return;
  }

  // Phase 2: other-nation world stories, codes 0x19..0x1d.
  code = 0x19;
  do {
    if (*majorCursor > 2) {
      break;
    }
    rec = 0;
    for (int i = ordinal + 1; i <= sharedEventRecordQueue->GetSize(); i++) {
      InterNationNewsRecord* entry = static_cast<InterNationNewsRecord*>(
          sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(i));
      if (entry->eventKind == code && entry->payload.treaty.subjectNation != nation) {
        rec = entry;
        ordinal = i;
        break;
      }
    }
    if (rec == 0 || rec->payload.treaty.counterpartNationMask == (1 << nation)) {
      ordinal = 0;
      code++;
    } else {
      newsStory* story = &stories[nation][*minorCursor][*majorCursor];
      story->feature38 = 0;
      story->parmKind[0] = 1;
      story->parmValue[0] = 1 << rec->payload.treaty.subjectNation;
      story->parmValue[1] = rec->payload.treaty.counterpartNationMask;
      story->parmKind[1] = 1;
      for (int k = 2; k < 4; k++) {
        story->parmValue[k] = 0;
        story->parmKind[k] = 0;
      }
      int wantId = -100 - rec->eventKind;
      tmpl = storyTemplateTable;
      for (t = 0; t < storyTemplateCount; t++, tmpl++) {
        if (tmpl->storyId == wantId) {
          break;
        }
      }
      if (t < storyTemplateCount) {
        story->entry = *tmpl;
        ++*minorCursor;
        if (*minorCursor == 3) {
          *minorCursor = 0;
          ++*majorCursor;
        }
      }
    }
  } while (code <= 0x1d);

  if (*majorCursor >= 3) {
    return;
  }

  // Phase 3: code-0xF multi-nation stories for this nation.
  ordinal = 0;
  for (;;) {
    rec = 0;
    for (int i = ordinal + 1; i <= sharedEventRecordQueue->GetSize(); i++) {
      InterNationNewsRecord* entry = static_cast<InterNationNewsRecord*>(
          sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(i));
      if (entry->eventKind == kInterNationEventShortage &&
          entry->payload.shortage.subjectNation == nation) {
        rec = entry;
        ordinal = i;
        break;
      }
    }
    if (rec == 0) {
      break;
    }
    newsStory* story = &stories[nation][*minorCursor][*majorCursor];
    story->feature38 = 0;
    story->parmValue[0] = 1 << rec->payload.shortage.relatedNation;
    story->parmKind[0] = 2;
    story->parmValue[1] = rec->payload.shortage.affectedNationMask;
    story->parmKind[1] = 1;
    for (int k = 2; k < 4; k++) {
      story->parmValue[k] = 0;
      story->parmKind[k] = 0;
    }
    int wantId = -0x14;
    if (rec->eventKind >= kInterNationEventNonAggressionPactAccepted && rec->eventKind <= 0x15) {
      short bits = 0;
      for (int b = 0; b < 0x17; b++) {
        if (rec->payload.shortage.affectedNationMask & (1 << b)) {
          bits++;
        }
      }
      if (bits > 1) {
        wantId = -0x15;
      }
    }
    tmpl = storyTemplateTable;
    for (t = 0; t < storyTemplateCount; t++, tmpl++) {
      if (tmpl->storyId == wantId) {
        break;
      }
    }
    if (t < storyTemplateCount) {
      story->entry = *tmpl;
      ++*minorCursor;
      if (*minorCursor == 3) {
        *minorCursor = 0;
        ++*majorCursor;
      }
    }
    if (*majorCursor > 2) {
      break;
    }
  }

  // Phase 5: one random army/map-context story.
  if (*majorCursor > 2) {
    return;
  }
  short pass = 0;
  {
    TSortedPtrList* list = g_pMapContextActionManager->mapContextActionRecordList04;
    int recordCount = list->GetSize();
    if (recordCount > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          list->GetPtrListEntryByOneBasedIndex(rand() % recordCount + 1));
      newsStory* story = &stories[nation][*minorCursor][*majorCursor];
      int wantId;
      if (record->actionType04 == 0 || record->actionType04 == 3 || record->actionType04 == 4) {
        story->parmKind[0] = 3;
        story->parmValue[0] = record->tileOrObject08.tileIndex;
        wantId = (record->participantIndex02 != 0) - 0x1a;
      } else {
        short ordinalValue =
            static_cast<TZone*>(record->tileOrObject08.object)->GetContextOrdinalOrInvalid();
        story->parmValue[0] = ordinalValue;
        story->parmKind[0] = 4;
        wantId = -0x1b - (record->actionType04 != 1);
      }
      story->feature38 = 1;
      story->parmKind[1] = 1;
      story->parmValue[1] = 1 << record->nationIds[0];
      story->parmKind[2] = 1;
      story->parmValue[2] = 1 << record->nationIds[1];
      story->parmValue[3] = 0;
      story->parmKind[3] = 0;
      tmpl = storyTemplateTable;
      for (t = 0; t < storyTemplateCount; t++, tmpl++) {
        if (tmpl->storyId == wantId) {
          break;
        }
      }
      if (t < storyTemplateCount) {
        story->entry = *tmpl;
        ++*minorCursor;
        if (*minorCursor == 3) {
          *minorCursor = 0;
          ++*majorCursor;
        }
      }
    }
  }

  // Phase 6: code-0x11 stories — two passes, first keyed on this nation, then on 999.
  for (;;) {
    if (*majorCursor > 2) {
      return;
    }
    short target = static_cast<short>(nation);
    if (pass != 0) {
      target = 999;
    }
    ordinal = 0;
    for (;;) {
      rec = 0;
      for (int i = ordinal + 1; i <= sharedEventRecordQueue->GetSize(); i++) {
        InterNationNewsRecord* entry = static_cast<InterNationNewsRecord*>(
            sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(i));
        if (entry->eventKind == kInterNationEventMiscellaneous &&
            entry->payload.misc.subjectNationOrAll == static_cast<int>(target)) {
          rec = entry;
          ordinal = i;
          break;
        }
      }
      if (rec == 0) {
        break;
      }
      newsStory* story = &stories[nation][*minorCursor][*majorCursor];
      story->feature38 = 0;
      if (rec->payload.misc.subjectNationOrAll == -1) {
        story->parmValue[0] = 0;
        story->parmKind[0] = 0;
      } else {
        story->parmKind[0] = 1;
        story->parmValue[0] = 1 << rec->payload.misc.subjectNationOrAll;
      }
      for (int k = 1; k < 4; k++) {
        story->parmValue[k] = 0;
        story->parmKind[k] = 0;
      }
      tmpl = storyTemplateTable;
      for (t = 0; t < storyTemplateCount; t++, tmpl++) {
        if (tmpl->storyId == -1000 - rec->payload.misc.storyCode) {
          break;
        }
      }
      if (t < storyTemplateCount) {
        story->entry = *tmpl;
        ++*minorCursor;
        if (*minorCursor == 3) {
          *minorCursor = 0;
          ++*majorCursor;
        }
      }
      if (*majorCursor > 2) {
        break;
      }
    }
    pass++;
    if (pass >= 2) {
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0055c970
void TNewsMgr::AddEvent(int nationSlot, NewsEvent* event, unsigned char isReplayBypass) {
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }
  if (isReplayBypass == 0 && g_pSimMgr->difficultyLevel != 0) {
    g_pGameFlowState->SendNewsEvent(nationSlot, event);
    return;
  }
  perNationEventBuckets[nationSlot]->InsertCopiedRecordSortedByComparator(event);
}

// FUNCTION: IMPERIALISM 0x0055c9f0
void TNewsMgr::AddTreatyEvent(InterNationEventKind eventKind, int nationA, int nationB,
                              unsigned char isReplayBypass) {
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }
  if (isReplayBypass == 0 && g_pSimMgr->difficultyLevel != 0) {
    if (g_pSimMgr->difficultyLevel == 1) {
      g_pGameFlowState->CreateAndSendTurnEvent20_ShortAndTwoBytes(
          static_cast<short>(eventKind), static_cast<unsigned char>(nationA),
          static_cast<unsigned char>(nationB));
    }
    return;
  }

  if (eventKind >= kInterNationEventNonAggressionPactAccepted && eventKind < 0x16) {
    ConcatenateTreaty(eventKind, nationA, nationB);
    return;
  }

  CPtrIterator iterator;
  iterator.list = sharedEventRecordQueue;
  InterNationNewsRecord* record = static_cast<InterNationNewsRecord*>(iterator.FirstPtr());
  while (iterator.More() != 0) {
    if (record->eventKind == eventKind) {
      if (record->payload.treaty.subjectNation == nationA &&
          (record->payload.treaty.counterpartNationMask & (1 << nationB)) != 0) {
        return;
      }
      if (record->payload.treaty.subjectNation == nationB &&
          (record->payload.treaty.counterpartNationMask & (1 << nationA)) != 0) {
        return;
      }
    }
    record = static_cast<InterNationNewsRecord*>(iterator.NextPtr());
  }

  if (nationA < 7) {
    InterNationNewsRecord recordA;
    recordA.eventKind = eventKind;
    recordA.payload.treaty.subjectNation = nationA;
    recordA.payload.treaty.counterpartNationMask = 1 << nationB;
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&recordA);
  }
  if (nationB < 7 && eventKind > kInterNationEventWarDeclaredAgainstSubject &&
      eventKind < kInterNationEventWarWithIndependentMinor) {
    InterNationNewsRecord recordB;
    recordB.eventKind = eventKind;
    recordB.payload.treaty.subjectNation = nationB;
    recordB.payload.treaty.counterpartNationMask = 1 << nationA;
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&recordB);
  }
}

// FUNCTION: IMPERIALISM 0x0055cbd0
void TNewsMgr::AddShortageEvent(int subjectNation, int affectedNation, int relatedNation,
                                unsigned char isReplayBypass) {
  if (g_pSimMgr->gateFlag7a != 0) {
    return;
  }
  if (isReplayBypass == 0 && g_pSimMgr->difficultyLevel != 0) {
    g_pGameFlowState->CreateAndSendTurnEvent21_ThreeBytes(
        static_cast<unsigned char>(subjectNation), static_cast<unsigned char>(affectedNation),
        static_cast<unsigned char>(relatedNation));
    return;
  }

  int entryIndex = 1;
  while (entryIndex <= sharedEventRecordQueue->GetSize()) {
    InterNationNewsRecord* existing = static_cast<InterNationNewsRecord*>(
        sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (existing->eventKind == kInterNationEventShortage &&
        existing->payload.shortage.relatedNation == relatedNation &&
        existing->payload.shortage.subjectNation == subjectNation) {
      existing->payload.shortage.affectedNationMask |= 1 << affectedNation;
      return;
    }
    ++entryIndex;
  }

  InterNationNewsRecord record;
  record.eventKind = kInterNationEventShortage;
  record.payload.shortage.subjectNation = subjectNation;
  record.payload.shortage.affectedNationMask = 1 << affectedNation;
  record.payload.shortage.relatedNation = relatedNation;
  sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&record);
}

// FUNCTION: IMPERIALISM 0x0055cd00
void TNewsMgr::AddMiscEvent(int nationSlotOrAll, int storyCode, unsigned char isReplayBypass) {
  TSimMgr* simManager = g_pSimMgr;
  if (simManager->gateFlag7a == 0) {
    if (isReplayBypass == 0) {
      unsigned char multiplayerActive = simManager->multiplayerSessionRole != 0;
      if (multiplayerActive != 0) {
        g_pGameFlowState->CreateAndSendTurnEvent22_ByteAndShort(
            static_cast<unsigned char>(nationSlotOrAll), static_cast<short>(storyCode));
        return;
      }
    }

    InterNationNewsRecord record;
    record.eventKind = kInterNationEventMiscellaneous;
    record.payload.misc.subjectNationOrAll = nationSlotOrAll;
    record.payload.misc.storyCode = storyCode;
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&record);
  }
}

// FUNCTION: IMPERIALISM 0x0055cda0
void TNewsMgr::ConcatenateTreaty(InterNationEventKind eventKind, int nationA, int nationB) {
  bool nationAHandled = nationA >= 7;
  bool nationBHandled = nationB >= 7;
  if ((eventKind >= kInterNationEventPeaceTreatyRejected &&
       eventKind <= kInterNationEventNonAggressionPactRejected) ||
      eventKind == kInterNationEventTradeConsulateEstablished ||
      eventKind == kInterNationEventEmbassyEstablished) {
    nationBHandled = true;
  }

  int entryIndex = 1;
  while (!(nationAHandled && nationBHandled) && entryIndex <= sharedEventRecordQueue->GetSize()) {
    InterNationNewsRecord* record = static_cast<InterNationNewsRecord*>(
        sharedEventRecordQueue->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (record->eventKind == eventKind) {
      if (!nationAHandled && record->payload.treaty.subjectNation == nationA) {
        nationAHandled = true;
        record->payload.treaty.counterpartNationMask |= 1 << nationB;
      }
      if (!nationBHandled && record->payload.treaty.subjectNation == nationB) {
        nationBHandled = true;
        record->payload.treaty.counterpartNationMask |= 1 << nationA;
      }
    }
    ++entryIndex;
  }

  if (!nationAHandled) {
    InterNationNewsRecord recordA;
    recordA.eventKind = eventKind;
    recordA.payload.treaty.subjectNation = nationA;
    recordA.payload.treaty.counterpartNationMask = 1 << nationB;
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&recordA);
  }
  if (!nationBHandled) {
    InterNationNewsRecord recordB;
    recordB.eventKind = eventKind;
    recordB.payload.treaty.subjectNation = nationB;
    recordB.payload.treaty.counterpartNationMask = 1 << nationA;
    sharedEventRecordQueue->InsertCopiedRecordSortedByComparator(&recordB);
  }
}

// Mac oracle: ClearStoryParms.
// FUNCTION: IMPERIALISM 0x0055d090
void TNewsMgr::ClearStoryParms(newsStory* story) {
  // 40%: semantically exact. The original biases the pointer once (add eax,0x10)
  // and writes at +0..+0xc; MSVC folds our equivalent back into displacements.
  // Not worth contorting the source for one addressing-mode difference.
  story->parmKind[0] = 0;
  story->parmKind[1] = 0;
  story->parmKind[2] = 0;
  story->parmKind[3] = 0;
}
