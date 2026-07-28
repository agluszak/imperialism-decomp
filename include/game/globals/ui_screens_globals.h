#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern CString g_cstrCountryNameSettingValue006A4220;
extern TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture006A4268;

extern POINT g_ptTechItemModalMessage;
extern POINT g_ptFormattedErrorModalMessage;
extern POINT g_ptLoungeNationReplacementModalMessage;
extern POINT g_ptQueryFloaterModalMessage;
extern POINT g_ptGameSetupModalMessage;
extern POINT g_ptCivilianOrderModalMessage;

extern char g_szLiteralRb_00698720[];

extern char g_szSaveDirectoryPrefix_00698724[];

extern char g_szLiteralA_0069872C[];

extern const char* const g_pszSingleSlotSavePrefix_0065DDD0; // "slot" @ 0x65ddd0

extern const char* const g_pszMultiplayerSavePrefix_0065DDD4; // "mult" @ 0x65ddd4

extern const char* const g_pszImpSaveExtension_0065DDD8; // ".imp" @ 0x65ddd8

// Map-action-context display-name cache key (0x6984b8): reset to -1 before each status
// regen pass; read/written by GenerateMapActionContextDisplayNameAndHeadline.
extern int g_mapActionContextDisplayNameCacheId_006984b8;

// Companion stride (0x6984bc) for the display-name cache key: a random step (1/7/0xb/0x17)
// added to the key after each headline resource pick.
extern int g_mapActionContextDisplayNameCacheStep_006984bc;

extern "C" {
extern const unsigned int g_anScenarioScriptInstructionTags[27];

extern unsigned char g_bScenarioScriptTerminationRequested;

extern int g_nScenarioScriptInstructionCount;

// Source path/gate for the USetupScreens.cpp line-0x2e6 assert in
// TNetSelectPicture::DoEvent (and siblings in that TU).
extern char g_szSetupScreensSourcePath_00698AB8[];

extern int g_SetupScreensAssertFlag_006A4264;

// TSimMgr.cpp — per-nation scenario setup source table.
// Seven default nation setup rows: {control mode, city minister policy,
// foreign minister policy, defense minister policy}. 0x698b18.
extern short g_aDefaultNationSetupPolicyProfiles[7][4];

extern "C" char g_bTurnFlowBootstrapComplete;

// "Conan" — developer-cheat probe filename statted by TSimMgr::ISimMgr.
extern char g_szConanCheatFileName_00698BEC[];

} // extern "C"
