#include "game/TCivMgr.h"

CRuntimeClass* TCivMgr::GetRuntimeClass() const { return 0; }

TCivMgr::~TCivMgr() {}

void TCivMgr::DispatchSelectedUnitToGlobalMapStateHandler(int * pUnitOrderEntry) {}

bool TCivMgr::HandleCivilianTileSelectionOrReportClick(short nTileIndex, short nClickMode) { return 0; }

bool TCivMgr::HandleCivilianTileOrderAction(short nTileIndex, short nInputHint, undefined2 param_3) { return 0; }

void TCivMgr::RelinkCivilianOrderTileAndInvalidateMapTiles(short nNewTileIndex, int * pCivOrderEntry, undefined2 param_3) {}
