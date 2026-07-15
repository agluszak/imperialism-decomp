#include "game/TNewsMgr.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TSortedPtrList.h"

// SYNTHETIC: IMPERIALISM 0x0055b6a0
// TNewsMgr::`scalar deleting destructor'
TNewsMgr::~TNewsMgr() {}
// SYNTHETIC: IMPERIALISM 0x0055b670
// TNewsMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055b6f0
// TNewsMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewsMgr, TObject)

TNewsMgr::TNewsMgr() {}

void TNewsMgr::Free() {}

void TNewsMgr::ReadFrom(TStream* stream) {}

void TNewsMgr::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x0055b710
void TInterNationEventQueueManager::InitializeInterNationEventQueueManager() {
  for (int i = 0; i < 7; i++) {
    perNationEventBuckets[i] = new TSortedPtrList();
    perNationEventBuckets[i]->recordSize14 = 0x24;
    perNationUiCounters7[i] = 0;
  }
  *(int*)((char*)this + 8) = 0;
  sharedEventRecordQueue = new TSortedPtrList();
  sharedEventRecordQueue->recordSize14 = 0x10;
}
