#include "game/ui_screens/TUberCluster.h"

IMPLEMENT_DYNCREATE(TUberCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00571460
TUberCluster::TUberCluster() : TCluster() {}

// The scalar deleting destructor is compiler-generated from the inherited virtual dtor.

// FUNCTION: IMPERIALISM 0x005714c0
TUberCluster::~TUberCluster() {}

// FUNCTION: IMPERIALISM 0x005714e0
char TUberCluster::IsTradeControlAtMinimum() {
  return 1;
}
