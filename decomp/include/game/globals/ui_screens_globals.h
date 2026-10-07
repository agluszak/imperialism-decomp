#pragma once
#include "game/globals/global_types.h"

extern CString g_cstrCountryNameSettingValue;
extern TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture;
extern short g_creditsPlaybackActive;
extern "C" int g_nRandomMapSelectedNationSlot;
extern "C" void (TSimMgr::* g_apfnScenarioScriptInstructionHandlers[27])(STurnInstructionCursor*);

extern POINT g_ptTechItemModalMessage;
extern POINT g_ptFormattedErrorModalMessage;
extern POINT g_ptLoungeNationReplacementModalMessage;
extern POINT g_ptQueryFloaterModalMessage;
extern POINT g_ptGameSetupModalMessage;
extern POINT g_ptCivilianOrderModalMessage;
extern "C" POINT g_ptTurnTransitionModalMessage;

extern char g_szLiteralRb[];

extern char g_szSaveDirectoryPrefix[];

extern char g_szLiteralA[];

extern const char* const g_pszSingleSlotSavePrefix; // "slot" @ 0x65ddd0

extern const char* const g_pszMultiplayerSavePrefix; // "mult" @ 0x65ddd4

extern const char* const g_pszImpSaveExtension; // ".imp" @ 0x65ddd8

extern int g_mapActionContextDisplayNameCacheId;

extern int g_mapActionContextDisplayNameCacheStep;

extern "C" {
extern const unsigned int g_anScenarioScriptInstructionTags[27];

extern bool g_bScenarioScriptTerminationRequested;

extern int g_nScenarioScriptInstructionCount;

extern char g_szSetupScreensSourcePath[];

extern int g_SetupScreensAssertFlag;

extern short g_aDefaultNationSetupPolicyProfiles[7][4];

extern "C" bool g_bTurnFlowBootstrapComplete;

// "Conan" — developer-cheat probe filename statted by TSimMgr::ISimMgr.
extern char g_szConanCheatFileName[];

extern const char s_Chunk[];

} // extern "C"
