#include "game/CIterator.h"

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

// FUNCTION: IMPERIALISM 0x00487ef0
void* CIterator::Reset() {
  POSITION pos = ownerList->listState.GetHeadPosition();
  if (pos != NULL) {
    current = ownerList->listState.GetNext(pos);
    nextPosition = pos;
    return current;
  }
  nextPosition = NULL;
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487f20
int CIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x00487f40
void* CIterator::Advance() {
  POSITION pos = nextPosition;
  if (pos != NULL) {
    current = ownerList->listState.GetNext(pos);
    nextPosition = pos;
    return current;
  }
  current = 0;
  return 0;
}
