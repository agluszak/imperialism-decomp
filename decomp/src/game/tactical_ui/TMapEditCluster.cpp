#include "game/tactical_ui/TMapEditCluster.h"

#include "game/ui_core/TCluster.h"

// FUNCTION: IMPERIALISM 0x005b2930
TMapEditCluster::~TMapEditCluster() {}

IMPLEMENT_DYNCREATE(TMapEditCluster, TCluster)

// FUNCTION: IMPERIALISM 0x005b2970
void TMapEditCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::DoEvent(commandId, sourceHandler, event);
}
