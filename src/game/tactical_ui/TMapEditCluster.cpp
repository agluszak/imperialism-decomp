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

// NOOP: verified empty in original 0x005b28b6 (no standalone TMapEditCluster::TMapEditCluster body exists: CreateObject 0x005b2880 inlines this default ctor, calling the TCluster base ctor directly at that site)
TMapEditCluster::TMapEditCluster() {}

// FUNCTION: IMPERIALISM 0x005b2970
void TMapEditCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::DoEvent(commandId, sourceHandler, event);
}
