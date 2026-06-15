#include "game/CIterator.h"

#include "game/TPtrList.h"

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

// FUNCTION: IMPERIALISM 0x00487ef0
void* CIterator::Reset() {
  POSITION pos = reinterpret_cast<TPtrList*>(ownerList)->listState.GetHeadPosition();
  if (pos != NULL) {
    current = reinterpret_cast<TPtrList*>(ownerList)->listState.GetNext(pos);
    nextPos = pos;
    return current;
  }
  nextPos = NULL;
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487f20
int CIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x00487f40
void* CIterator::Advance() {
  if (nextPos != NULL) {
    current = reinterpret_cast<TPtrList*>(ownerList)->listState.GetNext(nextPos);
    return current;
  }
  current = 0;
  return 0;
}
