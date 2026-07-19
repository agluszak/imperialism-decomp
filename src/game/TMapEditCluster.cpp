#include "game/TMapEditCluster.h"

#include "game/TCluster.h"

// SYNTHETIC: IMPERIALISM 0x005b2900
// TMapEditCluster::`scalar deleting destructor'
TMapEditCluster::~TMapEditCluster() {}
// SYNTHETIC: IMPERIALISM 0x005b2880
// TMapEditCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b2950
// TMapEditCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapEditCluster, TCluster)

TMapEditCluster::TMapEditCluster() {}

// FUNCTION: IMPERIALISM 0x005b2970
void TMapEditCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::HandleEvent(commandId, sourceHandler, event);
}
