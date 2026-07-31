#include "game/military/TRemoteMinor.h"

#include <new>

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"

// SYNTHETIC: IMPERIALISM 0x00541c10
// TRemoteMinor::CreateObject

// SYNTHETIC: IMPERIALISM 0x00541d70
// TRemoteMinor::GetRuntimeClass

// Binary descriptor base points at itself (0x65b020), not TMinor — reproducing the
// original IMPLEMENT_DYNCREATE(TRemoteMinor, TRemoteMinor) copy-paste bug byte-for-byte.
IMPLEMENT_DYNCREATE(TRemoteMinor, TRemoteMinor)

// FUNCTION: IMPERIALISM 0x00541c90
bool TRemoteMinor::IsRemote(void) const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00541cb0
void TRemoteMinor::PurchaseItem(short resourceKind, short amount, short price) {
  (void)resourceKind;
  (void)amount;
  (void)price;
}

// SYNTHETIC: IMPERIALISM 0x00541cd0
// TRemoteMinor::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00541d00
TRemoteMinor::~TRemoteMinor() {}

// FUNCTION: IMPERIALISM 0x00541d90
void TRemoteMinor::PlopDownCity(short selectedRegion, const char* mapCellLabel) {
  homeTileIndex = selectedRegion;
  CString label(mapCellLabel);
  short cityRecordIndex =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(homeTileIndex)].cityRecordIndex;
  g_pGlobalMapState->SetGlobalMapCellSharedLabel(cityRecordIndex, &label);
}
