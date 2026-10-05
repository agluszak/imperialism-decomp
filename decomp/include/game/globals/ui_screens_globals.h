#pragma once
#include "game/globals/global_types.h"

extern CString g_cstrCountryNameSettingValue006A4220;
extern TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture006A4268;
extern short g_creditsPlaybackActive_006a4084;
extern "C" int g_nRandomMapSelectedNationSlot00698AB0;
extern "C" void (TSimMgr::* g_apfnScenarioScriptInstructionHandlers[27])(STurnInstructionCursor*);

extern POINT g_ptTechItemModalMessage;
extern POINT g_ptFormattedErrorModalMessage;
extern POINT g_ptLoungeNationReplacementModalMessage;
extern POINT g_ptQueryFloaterModalMessage;
extern POINT g_ptGameSetupModalMessage;
extern POINT g_ptCivilianOrderModalMessage;
extern "C" POINT g_ptTurnTransitionModalMessage;

extern char g_szLiteralRb_00698720[];

extern char g_szSaveDirectoryPrefix_00698724[];

extern char g_szLiteralA_0069872C[];

extern const char* const g_pszSingleSlotSavePrefix_0065DDD0; // "slot" @ 0x65ddd0

extern const char* const g_pszMultiplayerSavePrefix_0065DDD4; // "mult" @ 0x65ddd4

extern const char* const g_pszImpSaveExtension_0065DDD8; // ".imp" @ 0x65ddd8

extern int g_mapActionContextDisplayNameCacheId_006984b8;

extern int g_mapActionContextDisplayNameCacheStep_006984bc;

extern "C" {
extern const unsigned int g_anScenarioScriptInstructionTags[27];

extern bool g_bScenarioScriptTerminationRequested;

extern int g_nScenarioScriptInstructionCount;

extern char g_szSetupScreensSourcePath_00698AB8[];

extern int g_SetupScreensAssertFlag_006A4264;

extern short g_aDefaultNationSetupPolicyProfiles[7][4];

extern "C" bool g_bTurnFlowBootstrapComplete;

// "Conan" — developer-cheat probe filename statted by TSimMgr::ISimMgr.
extern char g_szConanCheatFileName_00698BEC[];

extern const char s_Chunk_00698C0C[];

} // extern "C"
