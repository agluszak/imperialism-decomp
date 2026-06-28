#pragma once

#include "decomp_types.h"

#include "game/TDealList.h"
#include "game/TCountry.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TMacViewMgr.h"
#include "game/TMinor.h"

struct NationState;
class TDiplomacyMgr;
class TNavyMgr;
class TSimMgr;
class TAssetMgr;
class TInterNationEventQueueManager;

class TLanguageMgr;
class THelpMgr;

class TView;
class TControl;

// ============================================================================
// Diplomacy globals
// ============================================================================

extern "C" {
class TApplication;
class ImperialismApp;

// GLOBAL: IMPERIALISM 0x006a4280
// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern TMinor* g_apSecondaryNationStateSlots[36];
// GLOBAL: IMPERIALISM 0x006a429c
// Parallel to g_apMinorNationCapabilityObjects[16] — aux runtime terrain rows.
extern TMinor* g_apNationAuxRuntimeStateSlots[16];
// GLOBAL: IMPERIALISM 0x006a432c
extern TMinor* g_apMinorNationCapabilityObjects[16];
// GLOBAL: IMPERIALISM 0x006a4370
extern TGreatPower* g_apNationStates[7];
// GLOBAL: IMPERIALISM 0x006a438c
extern void* g_apNationStates_End;
// GLOBAL: IMPERIALISM 0x006a21b8
extern THelpMgr* g_pHelpMgr;
// GLOBAL: IMPERIALISM 0x006a43e8
extern TInterNationEventQueueManager* g_pInterNationEventQueueManager;
// GLOBAL: IMPERIALISM 0x006a1344
extern TApplication* g_pGlobalUiRootController;
// GLOBAL: IMPERIALISM 0x006a43c8
extern void* g_pGameFlowState;
// GLOBAL: IMPERIALISM 0x006a43d0
extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;
// GLOBAL: IMPERIALISM 0x006a43e4
extern TNavyMgr* g_pNavyOrderManager;
// GLOBAL: IMPERIALISM 0x006a3338
extern int* g_pMapContextActionManager;
// GLOBAL: IMPERIALISM 0x006a21c0
extern int DAT_006a21c0;
// GLOBAL: IMPERIALISM 0x006a1348
extern ImperialismApp* DAT_006a1348;
// GLOBAL: IMPERIALISM 0x006a1350
extern int DAT_006a1350;
// GLOBAL: IMPERIALISM 0x006a1354
extern void* DAT_006a1354;
}

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// GLOBAL: IMPERIALISM 0x006a4310
extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];
// GLOBAL: IMPERIALISM 0x006a2158
extern TDisplayMgr* g_pDisplayMgr;
// GLOBAL: IMPERIALISM 0x006a21a8
extern TMacViewMgr* g_pStrategicMapViewSystem;
// GLOBAL: IMPERIALISM 0x006a2148
extern TAssetMgr* g_pUiViewManager;
// GLOBAL: IMPERIALISM 0x006a20f8
extern TSimMgr* g_pLocalizationTable;
// GLOBAL: IMPERIALISM 0x006a327c
extern TLanguageMgr* g_pLanguageMgr;

// ============================================================================
// McAppUI globals
// ============================================================================

extern "C" {

// Gate checked before touching a control's native window (e.g. ValidateRect /
// InvalidateRect): non-zero once the UI subsystem/screen is realized.
// GLOBAL: IMPERIALISM 0x006950ac
extern int g_McAppUiActiveFlag_006950AC;

// Gate checked in the QuickDraw/GDI draw path before temporarily clearing the UI
// invalidation flag.
// GLOBAL: IMPERIALISM 0x006a1af8
extern int g_McAppUiDrawGate_006A1AF8;

// Gate checked before the invalidation-flag assert/log call in the child-detach path.
// GLOBAL: IMPERIALISM 0x006a1ae0
extern int g_McAppUiFlag_006A1AE0;

// Gate checked before the UI resource-entry allocation assert in TEventHandler slot 0x08.
// GLOBAL: IMPERIALISM 0x006a1ae4
extern int g_McAppUiFlag_006A1AE4;

// Further invalidation-flag assert gates (McAppUI.cpp lines 1914 / 1922).
// GLOBAL: IMPERIALISM 0x006a1afc
extern int g_McAppUiFlag_006A1AFC;
// GLOBAL: IMPERIALISM 0x006a1b00
extern int g_McAppUiFlag_006A1B00;

// Per-line one-shot invalidation-flag assert gates used by TWindow's UI slot bodies.
// GLOBAL: IMPERIALISM 0x006a1b04
extern int g_McAppUiFlag_006A1B04;
// GLOBAL: IMPERIALISM 0x006a1b08
extern int g_McAppUiFlag_006A1B08;
// GLOBAL: IMPERIALISM 0x006a1b10
extern int g_McAppUiFlag_006A1B10;
// GLOBAL: IMPERIALISM 0x006a1b14
extern int g_McAppUiFlag_006A1B14;
// GLOBAL: IMPERIALISM 0x006a1b18
extern int g_McAppUiFlag_006A1B18;
// GLOBAL: IMPERIALISM 0x006a1b1c
extern int g_McAppUiFlag_006A1B1C;
// GLOBAL: IMPERIALISM 0x006a1b0c
extern int g_McAppUiFlag_006A1B0C;

// Reentrancy guard for the root UpdateWindow pass driven by TView slot 0x4f.
// GLOBAL: IMPERIALISM 0x006a1af0
extern int g_McAppUiUpdateWindowRecursionGuard_006A1AF0;

// Active QuickDraw origin/render context view for slot 0x3e.
// GLOBAL: IMPERIALISM 0x006a1af4
extern class TView* g_McAppUiActiveRenderContext_006A1AF4;

// Default absolute layout position (x, y) used when a control has no owner context, in
// the position-propagation pass (TView::vmethod_0089).
// GLOBAL: IMPERIALISM 0x006a1a60
extern int g_McAppUiDefaultPosX_006A1A60;
// GLOBAL: IMPERIALISM 0x006a1a64
extern int g_McAppUiDefaultPosY_006A1A64;

// Mouse-capture drag/repeat state used by TControl's input slots.
// GLOBAL: IMPERIALISM 0x006a1a68
extern int g_McAppUiMouseCaptureStartPoint_006A1A68[2];
// GLOBAL: IMPERIALISM 0x006a1a70
extern int g_McAppUiMouseCaptureLastPoint_006A1A70[2];
// GLOBAL: IMPERIALISM 0x006a1a78
extern int g_McAppUiMouseCaptureCurrentPoint_006A1A78[2];
// GLOBAL: IMPERIALISM 0x006a1a80
extern class TControl* g_McAppUiMouseCaptureControl_006A1A80;
// GLOBAL: IMPERIALISM 0x006a1adc
extern unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC;

// Source-file path string ("D:\\Ambit\\McAppUI.cpp") passed with a line number to the
// UI invalidation-flag assert/log helper.
// GLOBAL: IMPERIALISM 0x006950b0
extern char g_szMcAppUiSourcePath_006950B0[];

// Header path string ("D:\\Ambit\\McAppUI.h") passed with a line number to city-production
// dialog assert/log helpers on the TControl branch.
// GLOBAL: IMPERIALISM 0x006943cc
extern char g_szMcAppUiHeaderPath_006943CC[];

// Source-file path string ("D:\\Ambit\\Cross\\UGameWindow.cpp") passed with a line number to
// the UI invalidation-flag assert helper from the TDlgWindow/UGameWindow assert hooks.
// GLOBAL: IMPERIALISM 0x00696bc0
extern char g_szUGameWindowSourcePath_00696bc0[];

// Gate checked by TControl::AssertCityProductionGlobalStateInitialized before the
// McAppUI.h line-0x56f assert path runs.
// GLOBAL: IMPERIALISM 0x006a143c
extern int g_McAppUiFlag_006A143C;

} // extern "C"

// Active root of the in-progress UI resource tree and the entry currently being registered.
// GLOBAL: IMPERIALISM 0x006a141c
extern TView* g_pUiResourceHead;
// GLOBAL: IMPERIALISM 0x006a1420
extern TView* g_pUiResourceContext;

// ============================================================================
// UI runtime globals
// ============================================================================

undefined4 SetGlobalUiInvalidationFlagAndReturnPrevious(undefined4 newValue);
