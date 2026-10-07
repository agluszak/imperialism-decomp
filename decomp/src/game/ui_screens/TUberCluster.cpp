#include "game/ui_screens/TUberCluster.h"

IMPLEMENT_DYNCREATE(TUberCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00571460
TUberCluster::TUberCluster() : TCluster() {}

// FUNCTION: IMPERIALISM 0x005714c0
TUberCluster::~TUberCluster() {}

// FUNCTION: IMPERIALISM 0x005714e0
bool TUberCluster::IsTradeControlAtMinimum() {
  return true;
}
