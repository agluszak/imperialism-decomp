#include "game/tactical_ui/TMapEditCluster.h"

#include "game/ui_core/TCluster.h"

// SYNTHETIC: IMPERIALISM 0x005b2900
// TMapEditCluster::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b2930
TMapEditCluster::~TMapEditCluster() {}
// SYNTHETIC: IMPERIALISM 0x005b2880
// TMapEditCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b2950
// TMapEditCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapEditCluster, TCluster)

// FUNCTION: IMPERIALISM 0x005b2970
void TMapEditCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::DoEvent(commandId, sourceHandler, event);
}
