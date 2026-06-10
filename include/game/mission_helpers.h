#pragma once

// Defend-province mission support scores (cdecl; float return in original binary).
float ComputeDefendProvinceMissionLocalSupportVectorScore(int nodeContext);
float ComputeDefendProvinceMissionCrossNationSupportVectorScore(int nodeContext);

// Mission factory (0x5350d0). Deferred: mission ctors still use bridge thunks with manual
// vptr stores; port once TAttackProvinceMission/TInvadeMission/… use real inheritance.
void* CreateMissionObjectByKindAndNodeContext(int sourceNation, int missionKind, int arg2,
                                              int arg3, int arg4);
