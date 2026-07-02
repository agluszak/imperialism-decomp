#pragma once

// reccmp `// GLOBAL:` address markers for symbols declared here live in
// src/game/global_data_tables.cpp only (one marker per address).

#include "decomp_types.h"

#include "game/mfc.h"
#include <afxtempl.h>
#include "game/app_init_globals.h"
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
class TMultiplayerMgr;
class TNetMgr;
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

// Per-resource-type navy-order descriptor (base 0x00698108, stride 0x24). Ghidra's
// auto-analysis had split this into five separately-named "tables"
// (g_Resolve_Map_Order_LookupTable_00698108, g_Calculate_Mission_Order_LookupTable_0069810C,
// g_Task_Force_Order_LookupTable_00698110, g_Navy_Order_Priority_LookupTable_00698118,
// g_ResourceDescriptorWeightWord0Base0069811c); every one of those "tables" is read at
// per-index byte offset `index * 0x24` from a base address exactly 4/8/0x10/0x14 bytes
// apart -- confirmed via TShip.cpp/TMapOrderEntry.cpp callsite disassembly, they are one
// struct array. Element count is not yet pinned down (32 vs 64 in the pre-split
// declarations); 64 is the conservative (larger) choice pending confirmation.
struct TNavyOrderResourceDescriptor {
  short resolveWeight; // +0x00 (was g_Resolve_Map_Order_LookupTable_00698108)
  short pad02;
  short calculateWeight; // +0x04 (was g_Calculate_Mission_Order_LookupTable_0069810C)
  short pad06;
  short taskForceWeight; // +0x08 (was g_Task_Force_Order_LookupTable_00698110's own +0x00)
  short pad0a;
  short stockCap; // +0x0c (was same table's +0x04; reused as navy-order "normalization base")
  short pad0e;
  int navyPriorityWeight; // +0x10 (was g_Navy_Order_Priority_LookupTable_00698118, read as a dword)
  short resourceDescriptorWeightWord0; // +0x14 (was g_ResourceDescriptorWeightWord0Base0069811c)
  short pad16;
  int enabledFlagOrBucketOffset; // +0x18 (was same table's +0x10; low short reused elsewhere
                                 // as a bucket offset, full dword tested for sign as an
                                 // enabled/disabled gate)
  short descriptorWeight;        // +0x1c (was DAT_00698124)
  short pad1e[3];                // +0x1e..+0x24
};
ASSERT_SIZE(TNavyOrderResourceDescriptor, 0x24);

extern "C" TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[64];

// Per-unit-type military stat records (7 shorts per type, record base 0x695cd2):
// column 0 = category flag (0x10 = counted toward power/cost), column 1 = power/cost
// points. See TMilitaryUnit::GetUnitTypeCostPoints (0x5c3400).
extern "C" short g_UnitTypeMilitaryStatTable_00695CD2[64][7];

// Per-unit-type stat table (7 shorts per type; unit types 0x00-0x1d) and per-stat
// divisor baseline used by TMilitaryUnit::GetUnitTypeStatPercent (0x5c3530).
extern "C" short g_UnitTypeStatTable_0066EB88[30][7];
extern "C" short g_UnitTypeStatDivisorTable_0066ED30[7];

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. Used by TGreatPower vtable slots 0x88-0x8c.
extern "C" {
extern float g_DAT_Value_00653308[];
extern float g_DAT_Value_00653328[];
extern float g_DAT_Value_00653340[];
extern float g_DAT_Value_00653360[];
extern float g_DAT_Value_00653378[];
extern float g_DAT_Value_00653398[];
extern float g_DAT_006533b0_Value_006533B0[];
extern float g_DAT_006533d0_Value_006533D0[];
extern float g_DAT_006533e8_Value_006533E8[];
extern float g_DAT_Value_00653408[];

// Float constants used by the TGreatPower relative-power-score family
// (vtable slots 0x8e-0x9e, bodies 0x004e07b0..0x004e1c20).
extern const float g_Compute_Advisory_Handler_LookupTable_00653700; // 0.0f
extern float g_Compute_Advisory_Handler_LookupTable_00653714;       // -0.25f
extern float g_Iterate_Linked_List_Value_00653718;                  // 0.25f
extern float g_Compute_City_Order_Value_0065371C;                   // 0.5f
extern float g_Compute_Advisory_Handler_LookupTable_00653720;       // -90.0f
extern float g_Compute_Advisory_Peer_LookupTable_00653724;          // -0.5f
extern const float g_Compute_Advisory_Zero_00653FD0;
extern float g_Compute_Advisory_Map_Value_00653FD4;
extern double g_Compute_Advisory_MinusSix_00653FE8;
extern double g_Compute_Advisory_MinusHundred_00653FF0;
extern double g_Compute_Advisory_Hundred_00654000;
extern double g_Compute_Advisory_OnePointFive_00654008;

// 0x653704-0x653710 — production-tier classification constants (TGreatPower slot
// 0x82, body 0x004e2880): -1.0, 2.0, 1.0, -2.0.
extern float g_Classify_Nation_Military_Value_00653704;
extern float g_Classify_Nation_Military_Value_00653708;
extern float g_Classify_Nation_Military_Value_0065370C;
extern float g_Classify_Nation_Military_Value_00653710;

// Per-order-type sort priority table (slot 0x55 selection sort).
extern short g_DAT_006966d0_Value_006966D0[];
// Per-unit-type tactical category code (slot 0x11 garrison sweep).
extern short g_awTacticalUnitCategoryCodeBySlot[];

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's city stock block by TGreatPower slot 0x39 (0x004df810).
extern short g_Rebuild_Primary_Nation_Value_00653570[6][0x17];
} // extern "C"

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
// The multiplayer/game-flow singleton (0x6a43c8); every turn-event emitter is a
// __thiscall method on it (original callsites load ECX from here).
extern TMultiplayerMgr* g_pGameFlowState;
// WNetMgr.cpp TU globals (0x6a5fxx band), consumed by TNetMgr::Send / TWNetSessionManager.
// The pending-packet queue and its two serialization siblings are file-scope MFC template
// statics (see the typed C++ section below); the previous six raw queue globals were the
// members of the CList at 0x6a5f40.
extern int g_NetworkDefaultNationId006a5fc0;
extern int g_NetworkBroadcastNationId006a5fc4;
extern int DAT_006a601c;
extern const char s_DataDirectoryPath_006942A8[];
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
// Cached CCommandLineInfo::m_bShowSplash (cmdInfo+0x04), not m_nShellCommand.
extern BOOL g_cachedShowSplashFlag;
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
// Global TNetMgr (0x6a6014), created by TMultiplayerMgr session init.
extern TNetMgr* g_pNetMgr006a6014;
// WNetMgr.cpp file-scope MFC template statics (all atexit-destroyed; static-init
// helpers 0x5e26d0/0x5e2720/0x5e2770). Vtables 0x66fa50 (CList) / 0x66fa68 (CArray)
// are this TU's twin copies of the template vtables (recover-class once merged them
// into TNetMgr's vtable annotation by adjacency). Element/name identification is
// behavioral: Serialize instantiations at 0x5e4610/0x5e4830, node size 0xc,
// ctor blockSize 10.
// UGameWindow/dialog-factory widget build stack (IncludeView TU band). The out-of-line
// "PushUiResourcePoolNode"/"PopUiResourcePoolNode" bodies at 0x479b00/0x479a80 are this
// list's CList<...>::AddTail/RemoveTail twin copies; the "current panel" global the
// factory bodies read at 0x6a13e8 is this object's m_pNodeTail (i.e. GetTail()).
extern CList<void*, void*> g_UiWidgetBuildStack006a13e0; // elements are TView* widgets
extern CArray<void*, void*> g_WNetSerializedPtrArrayA006a5f10;
extern CArray<void*, void*> g_WNetSerializedPtrArrayB006a5f28;
extern CList<void*, void*> g_WNetPendingPacketList006a5f40;
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

// Source-file path string ("D:\\Ambit\\McWindow.cpp") for CMcWindow's one-shot asserts,
// and the gate read before the unknown-wParam 0x468 assert fires.
extern char g_szMcWindowSourcePath_006950D8[];
extern int g_nMcWindowStateMsgAssertGate_006A1C74;

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
extern "C" const char g_szDecimalFormat[]; // "%d" @ 0x69430c

// Great-power pressure tuning tables (see global_data_tables.cpp for values).
extern "C" const int g_anNationBasePressureByLocale[6];
extern "C" const int g_anGreatPowerPressureMinFloorByLocale[6];
extern "C" const int g_anGreatPowerEscalationSeedByLocale[6];
extern "C" const int g_anGreatPowerPressureRiseCapByLocale[6];
extern "C" const int g_anGreatPowerPressureDecayStepByLocale[6];
extern "C" const int g_anGreatPowerPressureRiseStepByLocale[6];
extern "C" const int g_anGreatPowerCompileThresholdByLocale[6];
extern "C" const int g_anGreatPowerPressureHardAlertThresholdByLocale[6];
extern "C" const int g_anNationStartingTreasuryByLocale[6];
extern CString g_cstrGreatPowerPressureMessage; // @ 0x6a2df0
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
extern int g_turnEventDialogAnchorPoint[2];
extern CPtrList g_LiveViewRegistry;
extern CPtrList g_ModalViewStack;

// ============================================================================
// UI runtime globals
// ============================================================================

undefined4 SetGlobalUiInvalidationFlagAndReturnPrevious(undefined4 newValue);

// Read g_McAppUiActiveFlag_006950AC (0x489a70) — guard checked before any real painting.
int GetMcAppUiActiveFlag();
