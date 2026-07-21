#include "game/TTaskList.h"
#include "game/TTask.h"
// SYNTHETIC: IMPERIALISM 0x005aeaf0
// TTaskList::CreateObject

// SYNTHETIC: IMPERIALISM 0x005aeb70
// TTaskList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTaskList, TList)

// FUNCTION: IMPERIALISM 0x005aeb90
TTaskList::TTaskList() : TList() {
  ConstructTSortedListBaseState(10);
}

// SYNTHETIC: IMPERIALISM 0x005aec00
// TTaskList::`scalar deleting destructor'
TTaskList::~TTaskList() {}

// FUNCTION: IMPERIALISM 0x005aed50
unsigned char TTaskList::ContainsTask(short taskType) {
  for (int ordinal = 1; ordinal <= GetCount(); ++ordinal) {
    TTask* task = static_cast<TTask*>(GetEntryByOrdinal(ordinal));
    if (task->taskType04 == taskType) {
      return 1;
    }
  }
  return 0;
}
