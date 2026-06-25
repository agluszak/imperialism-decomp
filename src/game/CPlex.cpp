#include "game/mfc.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00601b74
int AllocateAndLinkBlockHead(int* blockHead, int blockSize, int elementSize) {
  int* block = reinterpret_cast<int*>(new char[blockSize * elementSize + 4]);
  *block = *blockHead;
  *blockHead = reinterpret_cast<int>(block);
  return reinterpret_cast<int>(block);
}

// LIBRARY: IMPERIALISM 0x00601b94
// CPlex::FreeDataChain
