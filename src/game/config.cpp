#include "game/config.h"

undefined4 ConstructMultiplayerManager(void);

// FUNCTION: IMPERIALISM 0x00405529
int* __fastcall Config::InitDefaults() {
  return (int*)ConstructMultiplayerManager();
}
