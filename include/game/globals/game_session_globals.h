#pragma once
// Cross-subsystem game-session state. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern "C" {

// Session infrastructure and the active game state.
extern TNetMgr* g_pNetMgr006a6014;
extern TMapMgr* g_pGlobalMapState;
extern TCivMgr* g_pSelectedCivilianOrderState;
extern TSimMgr* g_pSimMgr;
extern THelpMgr* g_pHelpMgr;
extern TNewsMgr* g_pNewsMgr;
// Every turn-event emitter is a method on this multiplayer/game-flow singleton.
extern TMultiplayerMgr* g_pGameFlowState;

// Map-action-context state shared by strategic map, navy, and turn flow.
extern TZone* g_pMapActionContextListHead;
extern TOcean* g_pActiveMapOrderContext;
// Resolved context retained for a downstream dialog branch.
extern TTaskForce* g_pCachedMapActionContext;
// Zone-graph BFS distance-cache storage.
extern int g_nMapActionContextCount;
extern void* g_pMapActionContextDistanceCache;
extern int g_nMapActionContextDistanceCacheSizedFor;

} // extern "C"
