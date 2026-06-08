#include "game/TUberCluster.h"
#include "game/ui_widget_thunks.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00571460
TUberCluster::TUberCluster() : TCluster() {}

// FUNCTION: IMPERIALISM 0x00571490
TUberCluster::~TUberCluster() {}

// FUNCTION: IMPERIALISM 0x005713c0
TUberCluster* __cdecl CreateTUberClusterInstance(void) {
  TUberCluster* cluster =
      reinterpret_cast<TUberCluster*>(AllocateWithFallbackHandler(sizeof(TUberCluster)));
  if (cluster != 0) {
    new (cluster) TUberCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00571440
void* __cdecl GetTUberClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(0x0065e5b0);
}
