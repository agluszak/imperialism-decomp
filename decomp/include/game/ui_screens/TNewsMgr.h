#pragma once

#include "game/nation_domain_types.h"
#include "game/app/TObject.h"
#include "game/ui_core/TPtrList.h"
#include "game/mfc.h"
#include "game/news_domain_types.h"

class TStream;

struct newsEntry {
  int storyId;            // match key; 0 in a story slot means "slot empty"
  int headlineTextOffset; // +0x04 \ byte range in news.tex
  int headlineTextLength;
  int storyTextOffset; // +0x0c \ second byte range in news.tex
  int storyTextLength;
  int reserved14; // byteswapped with the rest; no observed reader
};

struct newsStory {
  int parmValue[4]; // substitution-token payloads
  int parmKind[4];
  newsEntry entry; // copy of the matched template row
  bool feature;    // 1 for ranking/random filler stories, 0 for events
};

// VTABLE: IMPERIALISM 0x0065c598
class TNewsMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNewsMgr)
  virtual ~TNewsMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;

  newsEntry* storyTemplateTable;
  int storyTemplateCount;
  // Per-nation newspaper page: 3x3 story slots (entry.storyId == 0 = empty).
  newsStory stories[7][3][3];
  // Transient "news.tex" resource stream held open across the CreateNewspaper calls.
  CFile* newsTexStream;
  TPtrList* perNationEventBuckets[kMajorNationCount];
  TPtrList* sharedEventRecordQueue;
  short* perNationStoryLastUsedTick[kMajorNationCount];

  // NOOP: verified empty at original inlined allocation site 0x0057c58f
  TNewsMgr() {}

  bool EvaluateFeatureStory(const newsEntry* templateRow, newsStory* story, int nationSlot);

  bool AlwaysTrueStory(const newsEntry* templateRow, newsStory* story, int nationSlot);

  void ClearStoryParms(newsStory* story);
  void INewsMgr();
  newsEntry* FindEntry(int storyId);
  InterNationNewsRecord* FindEventType(int eventKind, int nation, int* ordinal,
                                       unsigned char differentNation);

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
