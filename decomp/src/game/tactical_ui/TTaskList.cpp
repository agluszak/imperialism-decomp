#include "game/tactical_ui/TTaskList.h"
#include "game/tactical_ui/TTask.h"
// SYNTHETIC: IMPERIALISM 0x005aeaf0
// TTaskList::CreateObject

// SYNTHETIC: IMPERIALISM 0x005aeb70
// TTaskList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTaskList, TList)

// FUNCTION: IMPERIALISM 0x005aeb90
TTaskList::TTaskList() : TList() {}

// SYNTHETIC: IMPERIALISM 0x005aec00
// TTaskList::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005aec30
TTaskList::~TTaskList() {}

// FUNCTION: IMPERIALISM 0x005aec80
void TTaskList::ITaskList() {}

// FUNCTION: IMPERIALISM 0x005aeca0
void TTaskList::AddTask(TTask* task) {
  AddTail(task);
}

// FUNCTION: IMPERIALISM 0x005aecc0
void TTaskList::ProcessTasks() {
  int ordinal = 1;
  while (ordinal <= GetCount()) {
    TTask* task = static_cast<TTask*>(GetEntryByOrdinal(ordinal));
    if (task->Execute(this)) {
      RemoveAtOrdinal(ordinal);
      task->Free();
      if (ordinal > 0) {
        --ordinal;
      }
    }
    ++ordinal;
  }
}

// FUNCTION: IMPERIALISM 0x005aed50
unsigned char TTaskList::ContainsTask(short citySlotIndex) {
  for (short ordinal = 1; ordinal <= GetCount(); ++ordinal) {
    TTask* task = static_cast<TTask*>(GetEntryByOrdinal(ordinal));
    if (task->citySlotIndex == citySlotIndex) {
      return 1;
    }
  }
  return 0;
}
