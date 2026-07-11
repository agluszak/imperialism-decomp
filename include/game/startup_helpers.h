#pragma once

#include "game/app_init_globals.h"
#include "game/mfc.h"

class TAmbitApplication;
class CIncludeView;

struct GlobalViewportRectDefaultsRecord;

extern "C" {
// 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue();

// 0x0049ded0 — allocates/initializes global runtime singletons from startup config.
const char* GetDataDirectoryPathLiteral();
}

// 0x00493250 — GetTickCount() / 16; the game's coarse UI tick unit.
unsigned int GetTickCountDiv16();

// 0x004974f0
extern "C++" undefined4 ReleaseGlobalClipRegionHandleListAndReset_006a1c98();

// Reads HKEY_CURRENT_USER\Software\<company>\<product>\<section>, value <valueName>,
// returning it as a CString; falls back to defaultValue if any registry step fails or
// the value isn't present. 0x00412840
CString ReadOrCreateRegistryStringValueWithFallback(LPCSTR company, LPCSTR product, LPCSTR section,
                                                    LPCSTR valueName, LPCSTR defaultValue);

// Opens (creating as needed) HKEY_CURRENT_USER\Software\<company>\<product> and returns the
// final HKEY, or nullptr if any step fails. Sibling of
// ReadOrCreateRegistryStringValueWithFallback's key-opening prologue, one level shallower (no
// <section> subkey). Caller owns the returned HKEY (RegCloseKey). 0x00412640
HKEY OpenOrCreateCompanyProductRegistryKey(LPCSTR company, LPCSTR product);

// 0x00412a70 — the main thread's CWinThread::m_pMainWnd (the SDI CMainFrame), via its
// real CFrameWnd::GetActiveView(). Always a CIncludeView in this app (the only registered
// document-template view class).
CIncludeView* GetMainViewHostFromActiveThread();

// 0x00497230 — lazily seeds default 640x480 viewport rect globals.
GlobalViewportRectDefaultsRecord** InitializeGlobalRectDefaultsIfUninitialized();
