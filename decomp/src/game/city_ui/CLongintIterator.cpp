#include "game/city_ui/TLongintList.h"

// FUNCTION: IMPERIALISM 0x00487fb0
long CLongintIterator::FirstLong() {
  nextPosition = ownerList->GetHeadPosition();
  if (nextPosition != NULL) {
    current = ownerList->GetNext(nextPosition);
    return current;
  }
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487fe0
int CLongintIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x00488000
long CLongintIterator::NextLong() {
  if (nextPosition != NULL) {
    current = ownerList->GetNext(nextPosition);
    return current;
  }
  current = 0;
  return 0;
}
