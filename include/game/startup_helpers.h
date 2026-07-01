#pragma once

#include "game/app_init_globals.h"
#include "game/mfc.h"

class TAmbitApplication;
class CIncludeView;

struct GlobalViewportRectDefaultsRecord;

extern "C" {
// 0x005e7a80
void* SetGlobalCallback6A7FACAndReturnPrevious(void* callback);

// 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue();

// 0x0049ded0 — allocates/initializes global runtime singletons from startup config.
void InitializeGlobalRuntimeSystemsFromConfig(TAmbitApplication* app);
}

// 0x004974f0
extern "C++" undefined4 ReleaseGlobalClipRegionHandleListAndReset_006a1c98();

// 0x00412a70 — the main thread's CWinThread::m_pMainWnd (the SDI CMainFrame), via its
// real CFrameWnd::GetActiveView(). Always a CIncludeView in this app (the only registered
// document-template view class).
CIncludeView* GetMainViewHostFromActiveThread();

// 0x00497230 — lazily seeds default 640x480 viewport rect globals.
GlobalViewportRectDefaultsRecord** InitializeGlobalRectDefaultsIfUninitialized();
