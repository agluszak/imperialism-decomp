// Real definitions for read-only global data referenced by hand-written code.
//
// These exist so reccmp can pair instruction operands that reference named global
// data (float coefficient tables, named global pointers) instead of bare immediate
// addresses. reccmp maps the original symbol (config/symbols.csv) to the recomp PDB
// symbol by name (the C-linkage leading underscore is stripped), so the *values* here
// are irrelevant to matching — only the symbol identity and its use site matter.
//
// Symbol names below are taken verbatim from config/symbols.csv (including the few
// historically double-named float tables) so the address mapping resolves.

class TControl;
class TView;
class TCursorControlPanel;

#include "game/mfc.h"
#include "game/global_data_tables.h"
#include "game/UiRuntimeContext.h"
#include "game/startup_helpers.h"
#include "game/TNetMgr.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TNavyMgr.h"
#include "game/TSimMgr.h"
#include "game/TAssetMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TLanguageMgr.h"
#include "game/THelpMgr.h"
#include "game/TCursorControlPanel.h"
#include "game/TAnimator.h"
#include "game/TQuickDrawSurfaceContext.h"

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// GLOBAL: IMPERIALISM 0x006a4310
TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount] = {0};
// GLOBAL: IMPERIALISM 0x006a2158
TDisplayMgr* g_pDisplayMgr = 0;
// GLOBAL: IMPERIALISM 0x006a21a8
TMacViewMgr* g_pStrategicMapViewSystem = 0;
// GLOBAL: IMPERIALISM 0x006a21bc
TViewMgr* g_pUiRuntimeContext = 0;
// GLOBAL: IMPERIALISM 0x006a2148
TAssetMgr* g_pUiViewManager = 0;
// GLOBAL: IMPERIALISM 0x006a327c
TLanguageMgr* g_pLanguageMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e0
TAnimator* g_pUiAnimator = 0;

extern "C" {

// Diplomacy globals
// GLOBAL: IMPERIALISM 0x006a4280
TMinor* g_apSecondaryNationStateSlots[36] = {0};
// GLOBAL: IMPERIALISM 0x006a432c
// Minor-nation capability object table, iterated as a pointer array. The slot-0x32 loop
// scans entries [0..15] inclusive (`cmp edx, 0x6a4368` == &table[15]); sizing the array to
// 16 lets MSVC emit the sentinel as `g_apMinorNationCapabilityObjects + 0x3c`.
TMinor* g_apMinorNationCapabilityObjects[16] = {0};
// GLOBAL: IMPERIALISM 0x006a429c
// Scanned with g_apMinorNationCapabilityObjects[16].
TMinor* g_apNationAuxRuntimeStateSlots[16] = {0};
// GLOBAL: IMPERIALISM 0x006a4370
TGreatPower* g_apNationStates[7] = {0};
// GLOBAL: IMPERIALISM 0x006a438c
void* g_apNationStates_End;
// GLOBAL: IMPERIALISM 0x006a20f8
TSimMgr* g_pLocalizationTable = 0;
// GLOBAL: IMPERIALISM 0x006a21b8
THelpMgr* g_pHelpMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e8
TInterNationEventQueueManager* g_pInterNationEventQueueManager = 0;
// GLOBAL: IMPERIALISM 0x006a1344
TApplication* g_pGlobalUiRootController = 0;
// GLOBAL: IMPERIALISM 0x006a43c8
void* g_pGameFlowState = 0;
// GLOBAL: IMPERIALISM 0x006a43d0
TDiplomacyMgr* g_pDiplomacyTurnStateManager = 0;
// GLOBAL: IMPERIALISM 0x006a43e4
TNavyMgr* g_pNavyOrderManager = 0;
// GLOBAL: IMPERIALISM 0x006a3338
int* g_pMapContextActionManager = 0;
char g_vtblTSortedByRelationshipList = 0;
// GLOBAL: IMPERIALISM 0x006a21c0
int DAT_006a21c0 = 0;
// GLOBAL: IMPERIALISM 0x00695278
int g_nSaveFormatVersion = -1;
// GLOBAL: IMPERIALISM 0x00694250
char g_szMovementParseCompareA_00694250[] = "";
// GLOBAL: IMPERIALISM 0x00694254
char g_szMovementParseCompareB_00694254[] = "";
// GLOBAL: IMPERIALISM 0x006a1348
class ImperialismApp* DAT_006a1348 = 0;
// GLOBAL: IMPERIALISM 0x006a1350
int DAT_006a1350 = 0;
// GLOBAL: IMPERIALISM 0x006a1354
void* DAT_006a1354 = 0;

// McAppUI.cpp module globals referenced by TView/TControl widget code. See
// include/game/global_data_tables.h.
// GLOBAL: IMPERIALISM 0x006950ac
int g_McAppUiActiveFlag_006950AC = 1;
// GLOBAL: IMPERIALISM 0x006a1af8
int g_McAppUiDrawGate_006A1AF8 = 0;
// GLOBAL: IMPERIALISM 0x006a1ae0
int g_McAppUiFlag_006A1AE0 = 0;
// GLOBAL: IMPERIALISM 0x006a1ae4
int g_McAppUiFlag_006A1AE4 = 0;
// GLOBAL: IMPERIALISM 0x006a1afc
int g_McAppUiFlag_006A1AFC = 0;
// GLOBAL: IMPERIALISM 0x006a1b00
int g_McAppUiFlag_006A1B00 = 0;
// GLOBAL: IMPERIALISM 0x006a1af0
int g_McAppUiUpdateWindowRecursionGuard_006A1AF0 = 0;
// GLOBAL: IMPERIALISM 0x006a1af4
TView* g_McAppUiActiveRenderContext_006A1AF4 = 0;
// GLOBAL: IMPERIALISM 0x006a1a60
int g_McAppUiDefaultPosX_006A1A60 = 0;
// GLOBAL: IMPERIALISM 0x006a1a64
int g_McAppUiDefaultPosY_006A1A64 = 0;
// GLOBAL: IMPERIALISM 0x006a1a68
int g_McAppUiMouseCaptureStartPoint_006A1A68[2] = {0, 0};
// GLOBAL: IMPERIALISM 0x006a1a70
int g_McAppUiMouseCaptureLastPoint_006A1A70[2] = {0, 0};
// GLOBAL: IMPERIALISM 0x006a1a78
int g_McAppUiMouseCaptureCurrentPoint_006A1A78[2] = {0, 0};
// GLOBAL: IMPERIALISM 0x006a1a80
TControl* g_McAppUiMouseCaptureControl_006A1A80 = 0;
// GLOBAL: IMPERIALISM 0x006a1adc
unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC = 0;
// GLOBAL: IMPERIALISM 0x006950b0
char g_szMcAppUiSourcePath_006950B0[] = "D:\\Ambit\\McAppUI.cpp";
// GLOBAL: IMPERIALISM 0x006943cc
char g_szMcAppUiHeaderPath_006943CC[] = "D:\\Ambit\\McAppUI.h";
// GLOBAL: IMPERIALISM 0x00696bc0
char g_szUGameWindowSourcePath_00696bc0[] = "D:\\Ambit\\Cross\\UGameWindow.cpp";
// GLOBAL: IMPERIALISM 0x006a143c
int g_McAppUiFlag_006A143C = 0;
// GLOBAL: IMPERIALISM 0x006a1b04
int g_McAppUiFlag_006A1B04 = 0;
// GLOBAL: IMPERIALISM 0x006a1b08
int g_McAppUiFlag_006A1B08 = 0;
// GLOBAL: IMPERIALISM 0x006a1b10
int g_McAppUiFlag_006A1B10 = 0;
// GLOBAL: IMPERIALISM 0x006a1b14
int g_McAppUiFlag_006A1B14 = 0;
// GLOBAL: IMPERIALISM 0x006a1b18
int g_McAppUiFlag_006A1B18 = 0;
// GLOBAL: IMPERIALISM 0x006a1b1c
int g_McAppUiFlag_006A1B1C = 0;
// GLOBAL: IMPERIALISM 0x006a1b0c
int g_McAppUiFlag_006A1B0C = 0;

// GLOBAL: IMPERIALISM 0x0064b8f0
int g_Reset_Quick_Draw_Value_0064B8F0 = 1;
// GLOBAL: IMPERIALISM 0x0064b8f4
int g_Reset_Quick_Draw_Value_0064B8F4 = 1;
// GLOBAL: IMPERIALISM 0x0064b8f8
extern const short g_Reset_Quick_Draw_WordState_0064B8F8 = 0;
// GLOBAL: IMPERIALISM 0x006a1d10
short g_Reset_Quick_Draw_State_006A1D10 = 0;
// GLOBAL: IMPERIALISM 0x006a1d08
int g_nQuickDrawStrokeStylePrimary = 0;
// GLOBAL: IMPERIALISM 0x006a1d0c
int g_nQuickDrawStrokeStyleSecondary = 0;
// GLOBAL: IMPERIALISM 0x006a1db4
int g_bQuickDrawStrokePairDirty = 0;
// GLOBAL: IMPERIALISM 0x006a1da8
int g_pGlobalClipRegionHandleObject = 0;
// GLOBAL: IMPERIALISM 0x006950fc
int g_Quick_Draw_Color_State_006950FC = 0x010000FF;
// GLOBAL: IMPERIALISM 0x00695100
int g_uQuickDrawStrokeColor = 0x01000000;
// GLOBAL: IMPERIALISM 0x006a1d52
int g_uQuickDrawCurrentColor = 0;
// GLOBAL: IMPERIALISM 0x006a1d80
int g_nQuickDrawOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a1d84
int g_nQuickDrawOriginY = 0;
// GLOBAL: IMPERIALISM 0x006a1ca0
TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
// Statically initialized to the sentinel address (the dword at 0x006950f8 holds
// 0x006a1ca0 in the original), not null — the restore path in
// BuildStrategicMapCommodityIconAtlasFrom700To722 captures this before the first
// SetActiveQuickDrawSurfaceContext and would otherwise restore a null context.
// GLOBAL: IMPERIALISM 0x006950f8
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead = &g_defaultQuickDrawSurfaceSentinel;
// GLOBAL: IMPERIALISM 0x006a1d60
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a30a8
TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a1da0
CDC* g_pQuickDrawMemoryDc = nullptr;
// GLOBAL: IMPERIALISM 0x006a1dbc
HGDIOBJ g_hQuickDrawSavedBitmap = nullptr;
// GLOBAL: IMPERIALISM 0x006a1db0
int g_nActiveQuickDrawSurfaceFlags = 0;

// Overlay clip cache parameters
// GLOBAL: IMPERIALISM 0x006a4450
int g_nOverlayClipCacheParamX = 0;
// GLOBAL: IMPERIALISM 0x006a4454
int g_nOverlayClipCacheParamY = 0;

// Trade summary selection map
// GLOBAL: IMPERIALISM 0x006960e0
int g_pTradeSummarySelectionMap[32] = {0};

// Trade sell propagation tags
const int kTradeSellPropagationTags[17] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

} // extern "C"

// Diplomacy helper functions (formerly in diplomacy_globals.cpp).
TGreatPower* GetNationStateBySlot(short slotId) {
  return g_apNationStates[slotId];
}

short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot) {
  return nationState->GetDiplomacyExternalStateByTarget(metricSlot);
}

TGreatPower* GetActiveNationState(void) {
  return g_apNationStates[g_pUiRuntimeContext->GetActiveNationId()];
}

int GetTradeSummarySelectionTagByIndex(short index) {
  return g_pTradeSummarySelectionMap[index];
}

// Active root of the in-progress UI resource tree and the entry currently being registered.
// GLOBAL: IMPERIALISM 0x006a141c
TView* g_pUiResourceHead = nullptr;
// GLOBAL: IMPERIALISM 0x006a1420
TView* g_pUiResourceContext = nullptr;

// FUNCTION: IMPERIALISM 0x00489a50
undefined4 SetGlobalUiInvalidationFlagAndReturnPrevious(undefined4 newValue) {
  undefined4 previous = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = newValue;
  return previous;
}

extern "C" {
// MFC CRuntimeClass descriptors (slot-0 GetRuntimeClass returns these). Reccmp pairs by
// symbol name, so the zero-initialized contents are irrelevant to matching.
CRuntimeClass PTR_s_TEventHandler_00649588 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x006495a0
CRuntimeClass PTR_s_TView_006495a0 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x006495e8
CRuntimeClass PTR_s_TWindow_006495e8 = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass PTR_s_TControl_00649600 = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass PTR_s_TButton_00649618 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x006496a8
CRuntimeClass PTR_s_TNumberText_006496a8 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x0066c3c0
CRuntimeClass PTR_s_TPictureNumberText_0066c3c0 = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass PTR_s_TCluster_006496c0 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x006496d8
CRuntimeClass PTR_s_TFloatWindow_006496d8 = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass PTR_s_TPictureButton_0065e538 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x00656a30
CRuntimeClass PTR_s_TGameWindow_00656a30 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x00654f30
CRuntimeClass PTR_s_TRearFloatWindow_00654f30 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x00656a48
CRuntimeClass PTR_s_TDlgWindow_00656a48 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x00697848
CRuntimeClass PTR_s_TMission_00697848 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x0065c630
CRuntimeClass PTR_s_TOcean_0065c630 = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass PTR_s_TTown_0066d780 = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x00654cd0
CRuntimeClass TDiplomacyMgr_classRuntimeClass_00654cd0 = {nullptr, 0, 0, nullptr, nullptr};
char LAB_00409a9d = 0;

// Default mission score constant (0.0), loaded by the TMission slot 0x68-0x7C float
// stubs (read pointer at 0x0065a468, immediately before the TMission vtable).
// GLOBAL: IMPERIALISM 0x0065a468
extern const float g_MissionDefaultScore_0065a468 = 0.0f;

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. Used by TGreatPower vtable slots 0x88-0x8c.
float g_DAT_Value_00653308[8] = {0};
float g_DAT_Value_00653328[8] = {0};
float g_DAT_Value_00653340[8] = {0};
float g_DAT_Value_00653360[8] = {0};
float g_DAT_Value_00653378[8] = {0};
float g_DAT_Value_00653398[8] = {0};
float g_DAT_006533b0_Value_006533B0[8] = {0};
float g_DAT_006533d0_Value_006533D0[8] = {0};
float g_DAT_006533e8_Value_006533E8[8] = {0};
float g_DAT_Value_00653408[8] = {0};

// Float constants used by the TGreatPower relative-power-score family
// (vtable slots 0x8e-0x9e, bodies 0x004e07b0..0x004e1c20). Values in the
// original image: 0.0f, -0.25f, 0.25f, 0.5f, -90.0f, -0.5f.
extern const float g_Compute_Advisory_Handler_LookupTable_00653700 = 0.0f;
// 0x653704-0x653710 — production-tier classification constants (TGreatPower slot
// 0x82, body 0x004e2880): -1.0, 2.0, 1.0, -2.0.
float g_Classify_Nation_Military_Value_00653704 = -1.0f;
float g_Classify_Nation_Military_Value_00653708 = 2.0f;
float g_Classify_Nation_Military_Value_0065370C = 1.0f;
float g_Classify_Nation_Military_Value_00653710 = -2.0f;
float g_Compute_Advisory_Handler_LookupTable_00653714 = -0.25f;
float g_Iterate_Linked_List_Value_00653718 = 0.25f;
float g_Compute_City_Order_Value_0065371C = 0.5f;
float g_Compute_Advisory_Handler_LookupTable_00653720 = -90.0f;
float g_Compute_Advisory_Peer_LookupTable_00653724 = -0.5f;
float g_ApplyIndexedResourceDeltaScale_00653728 = -1.0f / 255.0f;

// Per-unit-type military power weights (0xe-byte records, weight short at +0).
// Summed over militaryUnitList44 entries by the slot 0x8e-0x9c score family.
short g_Classify_Nation_Military_LookupTable_00695CD4[64][7] = {0};

// Per-order-type sort priority (short table at 0x6966d0), used by the TGreatPower
// slot 0x55 tracked-order selection sort (0x004e0290).
short g_DAT_006966d0_Value_006966D0[16] = {0};

// Per-unit-type tactical category code (short table at 0x695528); category 0 counts
// as garrison strength in TGreatPower slot 0x11 (0x004d87e0).
short g_awTacticalUnitCategoryCodeBySlot[64] = {0};

short g_Build_Hex_Area_LookupTable_00696E70[6] = {0};
short g_Build_Hex_Area_LookupTable_00696E80[6] = {0};

// Navy/order composite score tables (0x550b60 / SumNavyOrderPriority family).
short g_Resolve_Map_Order_LookupTable_00698108[9 * 64] = {0};
short g_Calculate_Mission_Order_LookupTable_0069810C[9 * 64] = {0};
short g_Task_Force_Order_LookupTable_00698110[0x24 * 32] = {0};
short g_Navy_Order_Priority_LookupTable_00698118[9 * 64] = {0};

struct MappedFlavorTextNationVariantEntry {
  short variantIndex;
  short pad;
};
MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32] = {0};

// Defend-province / mission priority-vector normalization (0x53e6e0 / 0x53ea70 family).
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8 = 0.0f;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0 = 0.0;
double g_Recompute_Nation_Order_LookupTable_0065A9F8 = 0.01;
double g_Recompute_Nation_Order_LookupTable_0065AA00 = 0.5;
double g_Recompute_Nation_Order_LookupTable_0065AA08 = 1.0;
unsigned short g_Recompute_Nation_Order_LookupTable_00697870[0x10] = {0};
unsigned short g_Populate_Beachhead_Mission_LookupTable_00697958[0x10] = {0};

// Random-roll scaling constants for TAutoGreatPower::AssignNeedSlotFromSourceSlot19C
// (0x004e7680): 1/255 and 32767.
double g_DAT_00653fc0_Value_00653FC0 = 0.00392156862745098;
double g_DAT_00653fc8_Value_00653FC8 = 32767.0;

// TAutoGreatPower slot 0x9d / 0xa7 scoring constants: -100.0f and 0.5 (double).
float g_Compute_Advisory_Map_Value_00653FD4 = -100.0f;
double g_Evaluate_Advisory_Case11_Value_00653FD8 = 0.5;
extern const float g_Compute_Advisory_Zero_00653FD0 = 0.0f;
double g_Compute_Advisory_MinusSix_00653FE8 = -6.0;
double g_Compute_Advisory_MinusHundred_00653FF0 = -100.0;
double g_Compute_Advisory_Hundred_00654000 = 100.0;
double g_Compute_Advisory_OnePointFive_00654008 = 1.5;

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's city stock block by TGreatPower slot 0x39 (0x004df810).
short g_Rebuild_Primary_Nation_Value_00653570[6][0x17] = {0};

// GLOBAL: IMPERIALISM 0x0066fad0
double DAT_0066fad0 = 0.092;

} // extern "C"

#include "game/TZone.h"
#include "game/TOcean.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TSelectedCivilianOrderState.h"
#include "game/TSoundPlayer.h"

// Named global pointers read with a direct absolute load in the original (vs the
// ReadGlobalPointer(imm) shortcut, which emits an extra indirection that cannot pair).
// Defined outside extern "C" so they keep C++ linkage and match typed header declarations.
TZone* g_pMapActionContextListHead = 0;
// GLOBAL: IMPERIALISM 0x006a3fbc
TOcean* g_pActiveMapOrderContext = 0;
TMapMgr* g_pGlobalMapState = 0;
TSelectedCivilianOrderState* g_pSelectedCivilianOrderState = 0;
TSoundPlayer* g_pSfxPlaybackSystem = 0;

extern "C" {
short g_awEngineerFortBuildCostByLevel[8] = {0};
int g_adwEngineerRailBuildCostByTerrainType[16] = {0};

int g_nMapActionContextCount = 0;
void* g_pMapActionContextDistanceCache = 0;
// g_pNationInteractionStateManager is defined in TDealList.cpp (0x6a43cc).

int g_NetworkDefaultNationId006a5fc0 = 0;
int g_NetworkBroadcastNationId006a5fc4 = 0;
void* g_pNetworkPacketQueueHead006a5f50 = 0;
void* g_pNetworkPacketQueueTail006a5f48 = 0;
void* g_pNetworkPacketQueueRoot006a5f44 = 0;
int g_NetworkPacketQueueCount006a5f4c = 0;
int g_NetworkPacketBlockCount006a5f58 = 0;
void* g_pNetworkPacketBlockChain006a5f54 = 0;
int g_NetworkManagerLastError006a5f6c = 0;
undefined4 DAT_0066ac88 = 0;
int DAT_006a601c = 0;

// InitInstance asset-path literals (LoadLanguageResourcesFromIrgFiles,
// EnsurePictWvDataGobLoadedBySlot).
// GLOBAL: IMPERIALISM 0x006942a8
extern "C" const char s_DataDirectoryPath_006942A8[] = "Data/";
// GLOBAL: IMPERIALISM 0x006942fc
extern "C" const char s_IrgGlobPattern_006942FC[] = "*.irg";
// GLOBAL: IMPERIALISM 0x006942b4
extern "C" const char s_NoLanguageFilesMessage_006942B4[] =
    "No language files are present. Unable to start Imperialism.";
// GLOBAL: IMPERIALISM 0x00698bf4
extern "C" const char s_PictWvGobPathFormat_00698BF4[] = "Data/PictWv%d.gob";
// GLOBAL: IMPERIALISM 0x0069b810
extern "C" const char s_MissingFileSuffix_0069B810[] = "' is missing.";
// GLOBAL: IMPERIALISM 0x0069b820
extern "C" const char s_MissingFilePrefix_0069B820[] = "A file required by the program, '";
// GLOBAL: IMPERIALISM 0x00695188
extern "C" const char s_MissingRequiredFileFormat_00695188[] =
    "A file required by the program, '%s,' is missing.";
// GLOBAL: IMPERIALISM 0x006951c4
extern "C" const char s_BmpResourceNameFormat_006951C4[] = "%d.BMP";
// GLOBAL: IMPERIALISM 0x0069b6b4
extern "C" const char s_TurnEventCursorNameFormat_0069B6B4[] = "~C%d";

// Profile string keys used by LoadProfileStringAndAssignSharedRef during multiplayer init.
// GLOBAL: IMPERIALISM 0x00698010
extern "C" const char s_GameName_00698010[] = "GameName";
// GLOBAL: IMPERIALISM 0x0069801c
extern "C" const char s_PlayerName_0069801c[] = "PlayerName";

// InitInstance registry/profile literals (.rdata pointer table @ 0x0063e038).
// GLOBAL: IMPERIALISM 0x006941a8
extern "C" const char s_ProfileLiteralIMPERIALISM_006941A8[] = "IMPERIALISM";
// GLOBAL: IMPERIALISM 0x006941b8
extern "C" const char s_ProfileKeyLanguage_006941B8[] = "Language";
// GLOBAL: IMPERIALISM 0x006941c4
extern "C" const char s_ProfileKeyAutoRes_006941C4[] = "AutoRes";
// GLOBAL: IMPERIALISM 0x006941d0
extern "C" const char s_ProfileSectionSettings_006941D0[] = "Settings";
// GLOBAL: IMPERIALISM 0x006941dc
extern "C" const char s_ProfileAppTitleImperialism_006941DC[] = "Imperialism";
// GLOBAL: IMPERIALISM 0x006941ec
extern "C" const char s_RegistryCompanyNameSSI_006941EC[] = "SSI";
// GLOBAL: IMPERIALISM 0x0063e038
extern "C" const char* const g_pRegistryCompanyKey_0063E038 = s_RegistryCompanyNameSSI_006941EC;
// GLOBAL: IMPERIALISM 0x0063e03c
extern "C" const char* const g_pRegistryAppKey_0063E03C = s_ProfileAppTitleImperialism_006941DC;
// GLOBAL: IMPERIALISM 0x0063e040
extern "C" const char* const g_pRegistrySettingsSection_0063E040 =
    s_ProfileSectionSettings_006941D0;
// GLOBAL: IMPERIALISM 0x0063e044
extern "C" const char* const g_pRegistrySettingsSectionAlt_0063E044 =
    s_ProfileSectionSettings_006941D0;
// GLOBAL: IMPERIALISM 0x0063e048
extern "C" const char* const g_pRegistryAutoResKey_0063E048 = s_ProfileKeyAutoRes_006941C4;
// GLOBAL: IMPERIALISM 0x0063e04c
extern "C" const char* const g_pRegistryLanguageKey_0063E04C = s_ProfileKeyLanguage_006941B8;
// GLOBAL: IMPERIALISM 0x0063e050
extern "C" const char* const g_pRegistryProfileAppName_0063E050 =
    s_ProfileLiteralIMPERIALISM_006941A8;

// Shared empty-string literal at 0x006a13a0 (the "" passed to CString ctors / string
// compares). Defined so reccmp pairs the address reference as a DATA symbol.
#include "decomp_types.h"
char g_szEmptyString[1] = {0};

// GLOBAL: IMPERIALISM 0x006a4490
extern "C" unsigned short g_awCivilianLegendSelectionCountsBySlot[16] = {0};

// GLOBAL: IMPERIALISM 0x698f58
extern "C" short g_anTargetTileProfileByCivilianClassAndSlot[45] = {0};

// Turn-flow cooldown defer counter and side flag (IsTurnCooldownCounterActiveOrResetFlag).
// GLOBAL: IMPERIALISM 0x006a43c4
short g_nTurnCooldownDeferCounter006A43C4 = 0;
// GLOBAL: IMPERIALISM 0x006a43c0 — set once scenario/turn-flow bootstrap completes.
char DAT_006a43c0 = 0;
// GLOBAL: IMPERIALISM 0x006a43f0 — nonzero during multiplayer scenario setup.
char DAT_006a43f0 = 0;
// GLOBAL: IMPERIALISM 0x00698b10
short g_nTurnCooldownSideFlag00698B10 = 1;

// Per-nation scenario setup table copied into TSimMgr's +0xe8 region by the ctor (0x57b9e0)
// and by InitializeTurnFlowStateDefaults. The copy loop reads with a -1 short bias (starts at
// &table[-1]), so the referenced symbol 0x698b1a is one short into the read span. Values
// recovered from the original binary; sized to cover every short the loop reads.
// GLOBAL: IMPERIALISM 0x00698b1a
extern "C" short g_anScenarioNationSetupTable_00698B1A[27] = {
    0x40f,  0x0,  0x41fc, 0x67, 0x410,  0x0,  0x41f4, 0x67, 0x410,  0x0,  0x41e4, 0x67, 0x810, 0x0,
    0x41e0, 0x67, 0x810,  0x0,  0x41d4, 0x67, 0x411,  0x0,  0x41d0, 0x67, 0x411,  0x0,  0x41cc};

// UI command-tag default params copied into every TControl (offsets 0x78/0x7c/0x80).
// Named so reccmp pairs the direct absolute loads in the TControl ctor.
int g_nUiResourceEntryDefaultParam0 = 0;
int g_nUiResourceEntryDefaultParam1 = 0;
unsigned short g_wUiResourceEntryDefaultParam2 = 0;

} // extern "C"

// 0x006a6014 — global turn-event-queue manager pointer (built by
// ConstructGlobalTurnEventQueueManager during multiplayer init, stored here and read by the
// turn-event dispatch path). GLOBAL: IMPERIALISM 0x006a6014
TNetMgr* DAT_006a6014 = 0;

#include "game/TApplication.h"

// GLOBAL: IMPERIALISM 0x006a18e0
TApplication* g_pApplicationUiRootController = 0;

// GLOBAL: IMPERIALISM 0x00648cf8
extern "C" char g_pClassDescTBehavior = 0;

// GLOBAL: IMPERIALISM 0x00648d10
extern "C" char g_pClassDescTDialogBehavior = 0;

// GLOBAL: IMPERIALISM 0x0064bda8
extern "C" char g_pClassDescTDialogView = 0;

// GLOBAL: IMPERIALISM 0x00648af8
extern "C" CRuntimeClass PTR_s_TApplication_00648af8 = {nullptr, 0, 0, nullptr, nullptr};

// GLOBAL: IMPERIALISM 0x006a44b0
extern "C" void* g_pActiveCityDialogLegendSelectionOwner = 0;

// GLOBAL: IMPERIALISM 0x006a44b4
// 4-byte flag (written as a dword by TStatusButton::HandleEvent); BOOL-style int.
int g_bCityDialogLegendSelectionInitialized = 0;

// GLOBAL: IMPERIALISM 0x006a590c
TCursorControlPanel* g_pCursorControlPanel = nullptr;

// McAppUI-wide modal-window stack (an MFC CPtrList of TWindow*, base 0x006a1ac0).
// TWindow::ExecuteViewModalStateWithPushPopChain pushes the active window on entry and
// pops it on exit, disabling/re-enabling the window beneath it across the modal run.
CPtrList g_ModalViewStack;

// McAppUI live-view registry: every TWindow/TView links itself in on construction and
// unlinks on teardown; the window-manager iterator (CWMgrIterator) sweeps it.
// GLOBAL: IMPERIALISM 0x006a1a40
CPtrList g_LiveViewRegistry;

// GLOBAL: IMPERIALISM 0x006a1b24
TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry = nullptr;

// GLOBAL: IMPERIALISM 0x006a1d18
GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord = {0, 0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a1dc0
GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord = nullptr;

// UDisplayMgr font-name literals and runtime CString slots (InitializeTurnOrderNavigationDialog).
// GLOBAL: IMPERIALISM 0x00695150
extern "C" const char g_szUiFontLiteralBelweBdBt[] = "Belwe Bd BT";
// GLOBAL: IMPERIALISM 0x00696b6c
extern "C" const char g_szUiFontLiteralPalatino[] = "Palatino";
// GLOBAL: IMPERIALISM 0x00696b78
extern "C" const char g_szUiFontLiteralBelweLight[] = "L Belwe Light";

// GLOBAL: IMPERIALISM 0x006a31bc
extern "C" short g_nTurnFlowNationComparisonAdvisoryTick = 0;

// GLOBAL: IMPERIALISM 0x00694fc8
extern "C" const char g_szUiNilPointerMessage[] = "Nil Pointer";
// GLOBAL: IMPERIALISM 0x00694fd8
extern "C" const char g_szUiFailureMessage[] = "Failure";

// GLOBAL: IMPERIALISM 0x006a3060
CString g_cstrUiFontBelweLight;
// GLOBAL: IMPERIALISM 0x006a3080
CString g_cstrUiFontPalatino;
// GLOBAL: IMPERIALISM 0x006a30a4
CString g_cstrUiFontBelweBdBt;

// One-shot invalidation-flag assert gates (UDisplayMgr.cpp lines 471/495).
// GLOBAL: IMPERIALISM 0x006a30ac
int g_nUiInvalidationAssertFlagLine471 = 0;
// GLOBAL: IMPERIALISM 0x006a30b0
int g_nUiInvalidationAssertFlagLine495 = 0;
