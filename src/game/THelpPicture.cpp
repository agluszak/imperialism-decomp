#include "game/THelpPicture.h"

#include "game/THelpMgr.h"
#include "game/TSortedPtrList.h"
#include "game/TDeluxeText.h"
#include "game/TStaticText.h"
#include "game/global_data_tables.h"

namespace {

HelpSetRecord* FindHelpSetById(short helpSetId) {
  TSortedPtrList* list = g_pHelpMgr->indexList;
  for (int index = 1; index <= list->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(list->GetPtrListEntryByOneBasedIndex(index));
    if (record->helpSetIdA == helpSetId) {
      return record;
    }
  }
  return 0;
}

void SetHelpNavigationControlState(THelpPicture* picture, unsigned int tag, bool enabled) {
  TView* control = picture->ResolveControlByTag(tag);
  control->SetEnabled(enabled ? 1 : 0, 1);
  control->SetState(enabled ? 0 : 1, 0);
}

} // namespace
#include "game/TDeluxeText.h"
#include "game/THelpMgr.h"
// SYNTHETIC: IMPERIALISM 0x00503bd0
// THelpPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00503c70
// THelpPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(THelpPicture, TPicture)

THelpPicture::THelpPicture() : TPicture(), currentHelpSet90(0), topicListText94(0) {}

// SYNTHETIC: IMPERIALISM 0x00503cc0
// THelpPicture::`scalar deleting destructor'
THelpPicture::~THelpPicture() {}

// FUNCTION: IMPERIALISM 0x00503d10
void THelpPicture::DoPostCreate(int arg) {}

// FUNCTION: IMPERIALISM 0x00503ed0
void THelpPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00504120
void THelpPicture::ShowNextHelpSet() {
  HelpSetRecord* next = FindHelpSetById(currentHelpSet90->helpSetIdC);
  if (next != 0) {
    currentHelpSet90 = next;
  }
  ShowTopicList();
}

// FUNCTION: IMPERIALISM 0x005041a0
void THelpPicture::ShowPreviousHelpSet() {
  HelpSetRecord* previous = FindHelpSetById(currentHelpSet90->helpSetIdB);
  if (previous != 0) {
    currentHelpSet90 = previous;
  }
  ShowTopicList();
}

// FUNCTION: IMPERIALISM 0x00504220
void THelpPicture::ShowTopic(short topic) {
  TStaticText* subject = static_cast<TStaticText*>(ResolveControlByTag(0x7375626a)); // 'subj'
  subject->SetTextFromStringResource(currentHelpSet90->helpSetIdA, topic + 1, 1);
  subject->SetEnabled(1, 1);
  subject->SetState(0, 1);

  TView* toggle = ResolveControlByTag(0x746f676c); // 'togl'
  toggle->SetEnabled(1, 0);
  toggle->SetState(1, 1);
  for (int index = 0; index < 5; ++index) {
    TView* topicName = ResolveControlByTag(0x6e616d31 + index); // 'nam1'..'nam5'
    topicName->SetEnabled(index < currentHelpSet90->category ? 1 : 0, 1);
    topicName->SetState(index + 1 == topic ? 1 : 0, 0);
  }
  SetHelpNavigationControlState(this, 0x70726576, currentHelpSet90->helpSetIdB != 0); // 'prev'
  SetHelpNavigationControlState(this, 0x6e657874, currentHelpSet90->helpSetIdC != 0); // 'next'
  topicListText94->SetEnabled(0, 1);
  RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005046c0
void THelpPicture::ShowTopicList() {
  TStaticText* subject = static_cast<TStaticText*>(ResolveControlByTag(0x7375626a)); // 'subj'
  subject->SetTextFromStringResource(currentHelpSet90->helpSetIdA, 1, 1);
  subject->SetEnabled(1, 1);
  subject->SetState(0, 1);

  TStaticText* toggle = static_cast<TStaticText*>(ResolveControlByTag(0x746f676c)); // 'togl'
  toggle->SetEnabled(1, 0);
  toggle->SetState(1, 1);
  toggle->SetTextFromStringResource(0x2749, 9, 1);
  for (int index = 0; index < 5; ++index) {
    TStaticText* topicName =
        static_cast<TStaticText*>(ResolveControlByTag(0x6e616d31 + index)); // 'nam1'..'nam5'
    bool enabled = index < currentHelpSet90->category;
    topicName->SetTextFromStringResource(currentHelpSet90->helpSetIdA, index + 2, 1);
    topicName->SetEnabled(enabled ? 1 : 0, 1);
    topicName->SetState(0, 0);
  }
  SetHelpNavigationControlState(this, 0x70726576, currentHelpSet90->helpSetIdB != 0); // 'prev'
  SetHelpNavigationControlState(this, 0x6e657874, currentHelpSet90->helpSetIdC != 0); // 'next'
  topicListText94->SetEnabled(0, 1);
  RefreshControl();
}
