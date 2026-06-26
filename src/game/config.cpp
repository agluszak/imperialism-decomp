#include "game/config.h"

#include "game/TMultiplayerMgr.h"

// FUNCTION: IMPERIALISM 0x00405529
int* Config::InitDefaults() {
  return reinterpret_cast<int*>(new TMultiplayerMgr());
}
