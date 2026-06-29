#pragma once

// reccmp `// GLOBAL:` address markers for symbols declared here live in
// src/game/global_data_tables.cpp only (one marker per address).

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/TCountry.h"
#include "game/startup_helpers.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TMacViewMgr.h"
#include "game/TMinor.h"

TGreatPower* GetNationStateBySlot(short slotId);
short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot);
TGreatPower* GetActiveNationState(void);
int GetTradeSummarySelectionTagByIndex(short index);

struct NationState;
struct TQuickDrawSurfaceContext;
class TDiplomacyMgr;
class TNavyMgr;
class TSimMgr;
class TAssetMgr;
class TInterNationEventQueueManager;

class TLanguageMgr;
class THelpMgr;
class TAnimator;

class TView;
class TViewMgr;
class TControl;
class TBackdropWindow;
class TOcean;
class TZone;
class TMapMgr;
class TTurnEventDialogFactoryRegistry;
class TSelectedCivilianOrderState;
class TSoundPlayer;
class TCursorControlPanel;
class TTechMgr;
class TWNetSessionManager;
class TDealList;
class TSoundResourceManager;
class TModuleLibraryCacheTableStateB;

struct GlobalViewportRectDefaultsRecord {
  int field0;
  int left;
  int top;
  int right;
  int bottom;
};

// ============================================================================
// Diplomacy globals
// ============================================================================

extern "C" {
class TApplication;
class ImperialismApp;

extern int g_nOverlayClipCacheParamX;
extern int g_nOverlayClipCacheParamY;
extern int g_Reset_Quick_Draw_Value_0064B8F0;
extern int g_Reset_Quick_Draw_Value_0064B8F4;
extern const short g_Reset_Quick_Draw_WordState_0064B8F8;
extern short g_Reset_Quick_Draw_State_006A1D10;
extern int g_nQuickDrawStrokeStylePrimary;
extern int g_nQuickDrawStrokeStyleSecondary;
extern int g_bQuickDrawStrokePairDirty;
extern int g_pGlobalClipRegionHandleObject;
extern int g_Quick_Draw_Color_State_006950FC;
extern int g_uQuickDrawCurrentColor;
extern int g_uQuickDrawStrokeColor;
extern int g_nQuickDrawOriginX;
extern int g_nQuickDrawOriginY;
extern TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext;
extern TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext;
extern CDC* g_pQuickDrawMemoryDc;
extern HGDIOBJ g_hQuickDrawSavedBitmap;
extern int g_nActiveQuickDrawSurfaceFlags;
extern int g_pTradeSummarySelectionMap[32];
extern const int kTradeSellPropagationTags[17];

// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern TMinor* g_apSecondaryNationStateSlots[36];
// Parallel to g_apMinorNationCapabilityObjects[16] — aux runtime terrain rows.
extern TMinor* g_apNationAuxRuntimeStateSlots[16];
extern TMinor* g_apMinorNationCapabilityObjects[16];
extern TGreatPower* g_apNationStates[7];
extern void* g_apNationStates_End;
extern TSimMgr* g_pLocalizationTable;
extern THelpMgr* g_pHelpMgr;
extern TInterNationEventQueueManager* g_pInterNationEventQueueManager;
extern TApplication* g_pGlobalUiRootController;
extern void* g_pGameFlowState;
extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;
extern TNavyMgr* g_pNavyOrderManager;
extern int* g_pMapContextActionManager;
extern int DAT_006a21c0;
extern int g_nSaveFormatVersion;
extern char g_szMovementParseCompareA_00694250[];
extern char g_szMovementParseCompareB_00694254[];
extern ImperialismApp* DAT_006a1348;
extern int DAT_006a1350;
extern void* DAT_006a1354;
extern CRuntimeClass g_pClassDescTCapacityOrder;
extern short g_industryActionCostWeightResCode09[16];
extern short g_industryActionCostWeightResCode08[16];
extern short g_industryActionCostWeightResCode10[16];
extern short g_industryActionCostWeightResCode0B[16];
extern short g_industryActionCostWeightResCode03[16];
extern short g_industryActionCostWeightResCode0C[16];
extern "C" CRuntimeClass TAmbitApplication_classRuntimeClass_0064c0b8;
extern HGDIOBJ g_pTempMapTileClipRegion;
extern char g_Sanitize_City_Counter_Value_006A24D4;
extern double DAT_0066fad0;
extern char g_pClassDescTStratReportView;
extern TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;
extern void* g_pGlobalCallback_006a7fac;
extern int DAT_006a2018;
extern TBackdropWindow* DAT_006a2050;
extern void* DAT_006a2054;
extern LPCSTR g_apFontFiles[];
extern int g_nDibOrientationFlag_006A1890;
extern CRuntimeClass s_CDib_RuntimeClass_00694b48;
extern void* g_pScopedMapQuickDrawViewContext;
extern void* g_pScopedMapQuickDrawDcHandleObject;
extern void* g_pReusableQuickDrawSurfaceListHead;
}

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
extern TCursorControlPanel* g_pCursorControlPanel;
extern TDealList* g_pNationInteractionStateManager;
extern GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord;
extern GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord;
extern TWNetSessionManager g_NetworkSessionManager006a5f60;
extern TTechMgr* g_pCityOrderCapabilityState;
extern TSoundResourceManager g_soundResourceManager;
extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];
extern TDisplayMgr* g_pDisplayMgr;
extern TMacViewMgr* g_pStrategicMapViewSystem;
extern TViewMgr* g_pUiRuntimeContext;
extern TAssetMgr* g_pUiViewManager;
extern TLanguageMgr* g_pLanguageMgr;
extern TAnimator* g_pUiAnimator;

// ============================================================================
// McAppUI globals
// ============================================================================

extern "C" {

// Gate checked before touching a control's native window (e.g. ValidateRect /
// InvalidateRect): non-zero once the UI subsystem/screen is realized.
extern int g_McAppUiActiveFlag_006950AC;

// Gate checked in the QuickDraw/GDI draw path before temporarily clearing the UI
// invalidation flag.
extern int g_McAppUiDrawGate_006A1AF8;

// Gate checked before the invalidation-flag assert/log call in the child-detach path.
extern int g_McAppUiFlag_006A1AE0;

// Gate checked before the UI resource-entry allocation assert in TEventHandler slot 0x08.
extern int g_McAppUiFlag_006A1AE4;

// Further invalidation-flag assert gates (McAppUI.cpp lines 1914 / 1922).
extern int g_McAppUiFlag_006A1AFC;
extern int g_McAppUiFlag_006A1B00;

// Per-line one-shot invalidation-flag assert gates used by TWindow's UI slot bodies.
extern int g_McAppUiFlag_006A1B04;
extern int g_McAppUiFlag_006A1B08;
extern int g_McAppUiFlag_006A1B10;
extern int g_McAppUiFlag_006A1B14;
extern int g_McAppUiFlag_006A1B18;
extern int g_McAppUiFlag_006A1B1C;
extern int g_McAppUiFlag_006A1B0C;

// Reentrancy guard for the root UpdateWindow pass driven by TView slot 0x4f.
extern int g_McAppUiUpdateWindowRecursionGuard_006A1AF0;

// Active QuickDraw origin/render context view for slot 0x3e.
extern class TView* g_McAppUiActiveRenderContext_006A1AF4;

// Default absolute layout position (x, y) used when a control has no owner context, in
// the position-propagation pass (TView::vmethod_0089).
extern int g_McAppUiDefaultPosX_006A1A60;
extern int g_McAppUiDefaultPosY_006A1A64;

// Mouse-capture drag/repeat state used by TControl's input slots.
extern int g_McAppUiMouseCaptureStartPoint_006A1A68[2];
extern int g_McAppUiMouseCaptureLastPoint_006A1A70[2];
extern int g_McAppUiMouseCaptureCurrentPoint_006A1A78[2];
extern class TControl* g_McAppUiMouseCaptureControl_006A1A80;
extern unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC;

// Source-file path string ("D:\\Ambit\\McAppUI.cpp") passed with a line number to the
// UI invalidation-flag assert/log helper.
extern char g_szMcAppUiSourcePath_006950B0[];

// Header path string ("D:\\Ambit\\McAppUI.h") passed with a line number to city-production
// dialog assert/log helpers on the TControl branch.
extern char g_szMcAppUiHeaderPath_006943CC[];

// Source-file path string ("D:\\Ambit\\Cross\\UGameWindow.cpp") passed with a line number to
// the UI invalidation-flag assert helper from the TDlgWindow/UGameWindow assert hooks.
extern char g_szUGameWindowSourcePath_00696bc0[];

// Gate checked by TControl::AssertCityProductionGlobalStateInitialized before the
// McAppUI.h line-0x56f assert path runs.
extern int g_McAppUiFlag_006A143C;

} // extern "C"

// Active root of the in-progress UI resource tree and the entry currently being registered.
extern TView* g_pUiResourceHead;
extern TView* g_pUiResourceContext;

// UDisplayMgr font literals and runtime CString slots (markers in global_data_tables.cpp).
extern "C" const char g_szUiFontLiteralBelweBdBt[];
extern "C" const char g_szUiFontLiteralPalatino[];
extern "C" const char g_szUiFontLiteralBelweLight[];
extern "C" const char g_szUiNilPointerMessage[];
extern "C" const char g_szUiFailureMessage[];
extern CString g_cstrUiFontBelweLight;
extern CString g_cstrUiFontPalatino;
extern CString g_cstrUiFontBelweBdBt;
extern int g_nUiInvalidationAssertFlagLine471;
extern int g_nUiInvalidationAssertFlagLine495;

// Game singleton pointers (markers in global_data_tables.cpp).
extern TZone* g_pMapActionContextListHead;
extern TOcean* g_pActiveMapOrderContext;
extern TMapMgr* g_pGlobalMapState;
extern TSelectedCivilianOrderState* g_pSelectedCivilianOrderState;
extern TSoundPlayer* g_pSfxPlaybackSystem;
extern TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry;
extern TApplication* g_pApplicationUiRootController;
extern CPtrList g_LiveViewRegistry;
extern CPtrList g_ModalViewStack;

// ============================================================================
// UI runtime globals
// ============================================================================

undefined4 SetGlobalUiInvalidationFlagAndReturnPrevious(undefined4 newValue);
