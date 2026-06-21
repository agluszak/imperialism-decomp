#include "game/TCivMgr.h"

// FUNCTION: IMPERIALISM 0x004d2030
CRuntimeClass* TCivMgr::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004d2070
// TCivMgr::`scalar deleting destructor'
TCivMgr::~TCivMgr() {}

// FUNCTION: IMPERIALISM 0x004d2270
void TCivMgr::DispatchSelectedUnitToGlobalMapStateHandler(int * pUnitOrderEntry) {
}

// FUNCTION: IMPERIALISM 0x004d2380
bool TCivMgr::HandleCivilianTileSelectionOrReportClick(short nTileIndex, short nClickMode) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d26d0
bool TCivMgr::HandleCivilianTileOrderAction(short nTileIndex, short nInputHint) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d4310
void TCivMgr::RelinkCivilianOrderTileAndInvalidateMapTiles(short nNewTileIndex, int * pCivOrderEntry) {
}
