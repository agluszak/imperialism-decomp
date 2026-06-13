// Real definitions for read-only global data referenced by hand-written code.
//
// These exist so reccmp can pair instruction operands that reference named global
// data (float coefficient tables, named global pointers) instead of bare immediate
// addresses. reccmp maps the original symbol (config/symbols.csv) to the recomp PDB
// symbol by name (the C-linkage leading underscore is stripped), so the *values* here
// are irrelevant to matching — only the symbol identity and its use site matter.
//
// Same mechanism as the g_p* pointer globals in diplomacy_globals.cpp.
// Symbol names below are taken verbatim from config/symbols.csv (including the few
// historically double-named float tables) so the address mapping resolves.

extern "C" {

// McAppUI.cpp module globals referenced by TView/TControl widget code. See
// include/game/mcappui_globals.h.
int g_McAppUiActiveFlag_006950AC = 0;
int g_McAppUiDrawGate_006A1AF8 = 0;
int g_McAppUiFlag_006A1AE0 = 0;
int g_McAppUiFlag_006A1AFC = 0;
int g_McAppUiFlag_006A1B00 = 0;
char g_szMcAppUiSourcePath_006950B0[] = "D:\\Ambit\\McAppUI.cpp";

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
float g_Compute_Advisory_Handler_LookupTable_00653700 = 0.0f;
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

// Defend-province / mission priority-vector normalization (0x53e6e0 / 0x53ea70 family).
float g_Recompute_Nation_Order_LookupTable_0065A9E8 = 0.0f;
double g_Recompute_Nation_Order_LookupTable_0065A9F0 = 0.0;
double g_Recompute_Nation_Order_LookupTable_0065A9F8 = 0.0;
double g_Recompute_Nation_Order_LookupTable_0065AA00 = 0.0;
double g_Recompute_Nation_Order_LookupTable_0065AA08 = 0.0;
unsigned short g_Recompute_Nation_Order_LookupTable_00697870[0x10] = {0};
unsigned short g_Populate_Beachhead_Mission_LookupTable_00697958[0x10] = {0};

// Random-roll scaling constants for TAutoGreatPower::AssignNeedSlotFromSourceSlot19C
// (0x004e7680): 1/255 and 32767.
double g_DAT_00653fc0_Value_00653FC0 = 0.00392156862745098;
double g_DAT_00653fc8_Value_00653FC8 = 32767.0;

// TAutoGreatPower slot 0x9d / 0xa7 scoring constants: -100.0f and 0.5 (double).
float g_Compute_Advisory_Map_Value_00653FD4 = -100.0f;
double g_Evaluate_Advisory_Case11_Value_00653FD8 = 0.5;

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's fieldB6 block by TGreatPower slot 0x39 (0x004df810).
short g_Rebuild_Primary_Nation_Value_00653570[6][0x17] = {0};

// Named global pointers read with a direct absolute load in the original (vs the
// ReadGlobalPointer(imm) shortcut, which emits an extra indirection that cannot pair).
void* g_pMapActionContextListHead = 0;
int g_nMapActionContextCount = 0;
void* g_pMapActionContextDistanceCache = 0;
void* g_pNationInteractionStateManager = 0; // 0x6a43cc

// Shared empty-string literal at 0x006a13a0 (the "" passed to CString ctors / string
// compares). Defined so reccmp pairs the address reference as a DATA symbol.
#include "decomp_types.h"
#include "game/TGlobalMapState.h"
#include "game/TMinor.h"
#include "game/TSelectedCivilianOrderState.h"
char g_szEmptyString[1] = {0};

// EH-body order/state globals (referenced by TGreatPower vtable slots 0x05/0x0c/0x32
// "pending action" state machines). Defined as real symbols so reccmp pairs the direct
// absolute loads (`mov reg, [g_pX]`) instead of bare immediates.
void* g_pCityOrderCapabilityState = 0;
void* g_pActiveMapOrderContext = 0;
class TGlobalMapState* g_pGlobalMapState = 0;
class TSelectedCivilianOrderState* g_pSelectedCivilianOrderState = 0;

// GLOBAL: IMPERIALISM 0x006a4490
extern "C" unsigned short g_awCivilianLegendSelectionCountsBySlot[16] = {0};

// GLOBAL: IMPERIALISM 0x698f58
extern "C" short g_anTargetTileProfileByCivilianClassAndSlot[45] = {0};

// Minor-nation capability object table at 0x006a432c, iterated as a pointer array. The
// slot-0x32 loop scans entries [0..15] inclusive (`cmp edx, 0x6a4368` == &table[15]); sizing
// the array to 16 lets MSVC emit the sentinel as `g_apMinorNationCapabilityObjects + 0x3c`.
void* g_apMinorNationCapabilityObjects[16] = {0};

// GLOBAL: IMPERIALISM 0x006a429c — scanned with g_apMinorNationCapabilityObjects[16].
TMinor* g_apNationAuxRuntimeStateSlots[16] = {0};

// UI command-tag default params copied into every TControl (offsets 0x78/0x7c/0x80).
// Named so reccmp pairs the direct absolute loads in the TControl ctor.
int g_nUiResourceEntryDefaultParam0 = 0;
int g_nUiResourceEntryDefaultParam1 = 0;
unsigned short g_wUiResourceEntryDefaultParam2 = 0;

} // extern "C"

#include "game/ApplicationUiRootController.h"

// GLOBAL: IMPERIALISM 0x006a18e0
ApplicationUiRootControllerState* g_pApplicationUiRootController = 0;

// GLOBAL: IMPERIALISM 0x006a44b0
extern "C" void* g_pActiveCityDialogLegendSelectionOwner = 0;

// GLOBAL: IMPERIALISM 0x006a44b4
unsigned char g_bCityDialogLegendSelectionInitialized = 0;
