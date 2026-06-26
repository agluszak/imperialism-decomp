#pragma once

#include "game/mfc.h"
#include "decomp_types.h"

class TAmbitApplication;
class TView;

extern "C" {
// 0x005e7a80
void* SetGlobalCallback6A7FACAndReturnPrevious(void* callback);

// 0x0049cc40
void SetGlobalDword6A2018(int value);

// 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue();

// 0x0049ded0 — allocates/initializes global runtime singletons from startup config.
void InitializeGlobalRuntimeSystemsFromConfig(TAmbitApplication* app);

// 0x00483340 — stores active dialog on the main view host and propagates UI context.
void SetUiRuntimeContextAndActivateMain(TView* mainViewHost, TView* activeDialog);
}

// 0x004974f0
extern "C++" undefined4 ReleaseGlobalClipRegionHandleListAndReset_006a1c98();

// 0x00412a70 — AfxGetThread virtual +0x7c then read *(obj+0x98).
void* GetMainViewHostFromActiveThread();
