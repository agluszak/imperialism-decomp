#include "game/TShortintList.h"

#include <limits.h>
#include <stdlib.h>

TShortArrayBase::~TShortArrayBase() {
  if (values != 0) {
    free(values);
  }
}

// FUNCTION: IMPERIALISM 0x004c18a0
void TShortArrayBase::InsertLast(short value) {
  unsigned int insertionIndex = count;
  if (capacity <= insertionIndex) {
    unsigned int minimumCapacity = insertionIndex + 1;
    unsigned int doubledCapacity = minimumCapacity * 2;
    unsigned int newCapacity = doubledCapacity;
    if (doubledCapacity > INT_MAX) {
      newCapacity = INT_MAX;
    }

    short* resizedValues = static_cast<short*>(realloc(values, minimumCapacity * sizeof(int)));
    if (resizedValues == 0) {
      values = static_cast<short*>(realloc(values, doubledCapacity));
      capacity = minimumCapacity;
    } else {
      values = resizedValues;
      capacity = newCapacity;
    }
  }

  if (count <= insertionIndex) {
    count = insertionIndex + 1;
  }
  values[insertionIndex] = value;
}
