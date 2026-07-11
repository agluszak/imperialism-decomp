#include "game/TTaskList.h"
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
int TTaskList::CreateTTechMgrInstance() {
  return 0;
}
