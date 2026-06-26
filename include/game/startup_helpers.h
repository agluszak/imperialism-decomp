#pragma once

#include "game/mfc.h"
#include "decomp_types.h"

extern "C" {
// 0x005e7a80
void* SetGlobalCallback6A7FACAndReturnPrevious(void* callback);

// 0x0049cc40
void SetGlobalDword6A2018(int value);

// 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue();

// 0x004149a0
bool __fastcall LoadLanguageResourcesFromIrgFiles(void* app, int dummyEdx);

// 0x0049ded0
void __fastcall InitializeGlobalRuntimeSystemsFromConfig(void* app, int dummyEdx);

// 0x00483340
void __fastcall SetUiRuntimeContextAndActivateMain(void* mainFrame, int dummyEdx, void* activeDialog);
}

// 0x004974f0
extern "C++" undefined4 ReleaseGlobalClipRegionHandleListAndReset_006a1c98();

