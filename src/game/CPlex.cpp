#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00601b74
int AllocateAndLinkBlockHead(int* blockHead, int blockSize, int elementSize) {
  int* block = reinterpret_cast<int*>(AllocateWithFallbackHandler(blockSize * elementSize + 4));
  *block = *blockHead;
  *blockHead = reinterpret_cast<int>(block);
  return reinterpret_cast<int>(block);
}

// LIBRARY: IMPERIALISM 0x00601b94
// CPlex::FreeDataChain
