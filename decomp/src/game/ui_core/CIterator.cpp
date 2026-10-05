#include "game/ui_core/CIterator.h"
#include "game/ui_core/TSortedList.h"

// FUNCTION: IMPERIALISM 0x00487ef0
void* CIterator::Reset() {
  nextPosition = ownerList->listState.GetHeadPosition();
  if (nextPosition != NULL) {
    current = ownerList->listState.GetNext(nextPosition);
    return current;
  }
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487f20
int CIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x00487f40
void* CIterator::Advance() {
  if (nextPosition != NULL) {
    current = ownerList->listState.GetNext(nextPosition);
    return current;
  }
  current = 0;
  return 0;
}
