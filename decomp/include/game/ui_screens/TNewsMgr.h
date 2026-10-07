#pragma once

#include "game/nation_domain_types.h"
#include "game/app/TObject.h"
#include "game/ui_core/TPtrList.h"
#include "game/mfc.h"
#include "game/news_domain_types.h"

class TStream;

struct newsEntry {
  int storyId;            // +0x00 — match key; 0 in a story slot means "slot empty"
  int headlineTextOffset; // +0x04 \ byte range in news.tex
  int headlineTextLength; // +0x08 /
  int storyTextOffset;    // +0x0c \ second byte range in news.tex
  int storyTextLength;    // +0x10 /
  int reserved14;         // +0x14 — byteswapped with the rest; no observed reader
};

struct newsStory {
  int parmValue[4]; // +0x00..0x0F — substitution-token payloads
  int parmKind[4];
  newsEntry entry; // +0x20..0x37 — copy of the matched template row
  bool feature;    // +0x38 — 1 for ranking/random filler stories, 0 for events
  unsigned char pad39[3];
};

// VTABLE: IMPERIALISM 0x0065c598
class TNewsMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNewsMgr)
  virtual ~TNewsMgr() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x55b8c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x55b8a0
  virtual void Free() override;                    // slot 0x07 0x55b820

  newsEntry* storyTemplateTable; // +0x004
  int storyTemplateCount;        // +0x008
  // Per-nation newspaper page: 3x3 story slots (entry.storyId == 0 = empty).
  newsStory stories[7][3][3]; // +0x00c..0xecf
  // Transient "news.tex" resource stream held open across the CreateNewspaper calls.
  CFile* newsTexStream;                                 // +0xed0
  TPtrList* perNationEventBuckets[kMajorNationCount];   // +0xed4
  TPtrList* sharedEventRecordQueue;                     // +0xef0
  short* perNationStoryLastUsedTick[kMajorNationCount]; // +0xef4

  // NOOP: verified empty at original inlined allocation site 0x0057c58f
  TNewsMgr() {}

  bool EvaluateFeatureStory(const newsEntry* templateRow, newsStory* story,
                            int nationSlot); // 0x0055cf20

  bool AlwaysTrueStory(const newsEntry* templateRow, newsStory* story,
                       int nationSlot); // 0x0055d0c0

  void ClearStoryParms(newsStory* story); // 0x0055d090
  void INewsMgr();
  newsEntry* FindEntry(int storyId); // 0x55c930, Mac oracle
  InterNationNewsRecord* FindEventType(int eventKind, int nation, int* ordinal,
                                       unsigned char differentNation); // 0x55c870

  // Mac-oracle event-queue API (gameplay side).
  void AddTreatyEvent(InterNationEventKind eventKind, int nationA, int nationB,
                      bool isReplayBypass);
  void AddEvent(int nationSlot, NewsEvent* event, bool isReplayBypass);
  void AddShortageEvent(int subjectNation, int affectedNation, int relatedNation,
                        bool isReplayBypass);
  void AddMiscEvent(int nationSlotOrAll, int storyCode, bool isReplayBypass);
  void ConcatenateTreaty(InterNationEventKind eventKind, int nationA, int nationB);

  void StartNewsPhase();
  // Loads and byteswaps Data/news.tab into storyTemplateTable.
  void LoadNewsTable();
  void CreateNewspaper(int nation);
  void CreateEventStories(int nation, int* majorCursor, int* minorCursor);
};

ASSERT_SIZE(TNewsMgr, 0xf10);
