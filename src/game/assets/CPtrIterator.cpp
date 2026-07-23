#include "game/CPtrIterator.h"

#include "game/TSortedPtrList.h"

// FUNCTION: IMPERIALISM 0x005e1fa0
void* CPtrIterator::FirstPtr() {
  nextIndex = 2;
  return list->GetPtrListEntryByOneBasedIndex(1);
}

// FUNCTION: IMPERIALISM 0x005e1fd0
int CPtrIterator::More() {
  return nextIndex <= list->GetSize() ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x005e2000
void* CPtrIterator::NextPtr() {
  int index = nextIndex;
  nextIndex = index + 1;
  return list->GetPtrListEntryByOneBasedIndex(index);
}
