#pragma once

#include "game/TObject.h"
#include "game/TSortedPtrList.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class CFile_Virtuals;

// 0x18-byte big-endian row of Data/news.tab (byteswapped at load, 0x55ba30).
// Mac oracle type name: newsEntry. Keyed by storyId:
//   >0  : ranking/feature stories (1 = generic feature; 10,20,30.. = decade features)
//   -100-code / -101-code : bilateral event story (the -101 variant when the event's
//                           nation mask has more than one bit and code in [5,0x15])
//   -20 / -21 : code-0xF (multi-nation) story, -21 when the mask popcount > 1
//   -25 / -26, -27 / -28 : random army/map-context stories
//   -1000-n : code-0x11 stories (n = the record's payload value)
struct newsEntry {
  int storyId;    // +0x00 — match key; 0 in a story slot means "slot empty"
  int textArgA0;  // +0x04 \ read as a pair by the page renderer (0x55d200)
  int textArgA1;  // +0x08 / (headline text codes — hedged)
  int textArgB0;  // +0x0c \ second pair
  int textArgB1;  // +0x10 / (body text codes — hedged)
  int reserved14; // +0x14 — byteswapped with the rest; no observed reader
};

// 0x3C-byte story card, 9 per nation page (Mac oracle: newsStory).
struct newsStory {
  int parmValue[4]; // +0x00..0x0F — substitution-token payloads
  // +0x10..0x1F — token kinds, decoded by 0x55d910: 0 = empty, 1 = nation bitmask
  // (1 << slot), 2 = nation bitmask (code-0xF variant), 3 = raw integer,
  // 4 = zone ordinal (short).
  int parmKind[4];
  newsEntry entry;         // +0x20..0x37 — copy of the matched template row
  unsigned char feature38; // +0x38 — 1 for ranking/random filler stories, 0 for events
  unsigned char pad39[3];
};

// The newspaper / inter-nation event manager (Mac oracle: TNewsMgr; the singleton at
// g_pInterNationEventQueueManager 0x6a43e8 is `new TNewsMgr()` + INewsMgr — proven by
// RebuildGlobalOrderManagersAndCapabilityState 0x57c3b0 storing exactly that). Gameplay
// code queues inter-nation event records into the per-nation buckets / shared queue;
// the turn machine's news phase (StartNewsPhase, turn case 0xf) turns them into the
// per-nation 3x3 newspaper story pages.
// VTABLE: IMPERIALISM 0x0065c598
class TNewsMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNewsMgr)
  virtual ~TNewsMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x55b8c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x55b8a0
  virtual void Free() override;                    // slot 0x07 0x55b820
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)

  // Transient story-template table loaded from Data/news.tab by LoadNewsTable and
  // freed at the end of StartNewsPhase — valid only during the news phase.
  newsEntry* storyTemplateTable; // +0x004
  int storyTemplateCount;        // +0x008
  // Per-nation newspaper page: 3x3 story slots (entry.storyId == 0 = empty).
  newsStory stories[7][3][3]; // +0x00c..0xecf
  // Transient "news.tex" resource stream held open across the CreateNewspaper calls.
  CFile_Virtuals* newsTexStream; // +0xed0
  // Per-nation event buckets (recordSize14 = 0x24) and the shared event record queue
  // (recordSize14 = 0x10; records are {int code, int nation, int mask, int extra}).
  TSortedPtrList* perNationEventBuckets[7]; // +0xed4
  TSortedPtrList* sharedEventRecordQueue;   // +0xef0
  // Per-nation last-used turn tick per story template (lazily new short[count] in
  // StartNewsPhase); drives the least-recently-used filler-story pick.
  short* perNationStoryLastUsedTick[7]; // +0xef4

  TNewsMgr();

  // Mac-style second-phase init (Mac: INewsMgr): creates the buckets/queue and nulls
  // the tick arrays. 0x55b710.
  void InitializeInterNationEventQueueManager();

  // Event-queue writers (gameplay side).
  void QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
                                          char isReplayBypass);
  void QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                             char isReplayBypass);
  void QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA, int nationB,
                                                   char isReplayBypass);
  // 0x55cd00 — type-0x11 event: with the bypass flag clear in a live multiplayer
  // session it re-emits over the network as turn-event 0x22 instead of queueing.
  void QueueInterNationEventType11(int eventParam, int value, char isReplayBypass);
  void AddOrUpdateBilateralActionRelationEntry(int eventCode, int nationA, int nationB);

  // News phase (turn case 0xf; Mac: StartNewsPhase): loads the template table, builds
  // each eligible nation's newspaper, then drops the consumed event records. 0x55b8e0.
  void StartNewsPhase();
  // Loads and byteswaps Data/news.tab into storyTemplateTable. 0x55ba30.
  void LoadNewsTable();
  // Builds one nation's 3x3 page: event stories first, then least-recently-used
  // random filler/feature stories. 0x55bc10 (Mac: CreateNewspaper).
  void CreateNewspaper(int nation);
  // Fills event stories for one nation, advancing the (major, minor) cursors through
  // the 3x3 page. 0x55c010 (Mac: CreateEventStories(long, long&, long&)).
  void CreateEventStories(int nation, int* majorCursor, int* minorCursor);

private:
  TSortedPtrList* GetInterNationQueueByEventCode(int eventCode);
};

ASSERT_SIZE(TNewsMgr, 0xf10);
