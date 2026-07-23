#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#pragma once

#include "game/ui_screens/CString.h"

// reccmp `// GLOBAL:` address markers for symbols declared here live in
// src/game/global_data_tables.cpp only (one marker per address).

#include "decomp_types.h"

#include <new.h> // _PNH (CRT new-handler type)

#include "game/mfc.h"
#include "game/military_domain_types.h"
#include <afxtempl.h>
#include "game/app_init_globals.h"
#include "game/city_ui/TCountry.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/strategic_terrain.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/nation/TMinor.h"
#include "game/ui_core/TView.h"
#include "game/core/TMouseCaptureState.h"
#include "game/net/TWNetSessionManager.h"
#include "game/assets/timer_slots.h"

TGreatPower* GetNationStateBySlot(short slotId);
short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot);
TGreatPower* GetActiveNationState(void);
int GetTradeSummarySelectionTagByIndex(short index);

struct NationState;
struct TextStyle;
struct TQuickDrawSurfaceContext;
struct TCdAudioDevice;
class TArmyMgr;
class TAdmiral;
class TDiplomacyMgr;
class TNavyMgr;
class TShip;
class TSimMgr;
class TAssetMgr;
class TNewsMgr;

class TLanguageMgr;
class THelpMgr;
class TAnimator;

class TView;
class TViewMgr;
class TControl;
class TBackdropWindow;
class TOcean;
class TZone;
class TTaskForce;
class TMapMgr;
class TCivMgr;
class TTurnEventDialogFactoryRegistry;
class TSetupRandomMapPicture;
class TSoundPlayer;
class TInfoBarText;
class TTechMgr;
class TMultiplayerMgr;
class TNetMgr;
class TTradeMgr;
class TSoundResourceManager;
class TModuleLibraryCacheTableStateB;
class CDib;

struct GlobalViewportRectDefaultsRecord {
  int field0;
  RECT viewportBounds;
};

// Per-resource-type navy-order descriptor (base 0x00698108, stride 0x24). Ghidra's
// auto-analysis had split this into five separately-named "tables"
// (g_Resolve_Map_Order_LookupTable_00698108, g_Calculate_Mission_Order_LookupTable_0069810C,
// g_Task_Force_Order_LookupTable_00698110, g_Navy_Order_Priority_LookupTable_00698118,
// g_ResourceDescriptorWeightWord0Base0069811c); every one of those "tables" is read at
// per-index byte offset `index * 0x24` from a base address exactly 4/8/0x10/0x14 bytes
// apart -- confirmed via TShip.cpp/TTaskForce.cpp callsite disassembly, they are one
// struct array. The initializer and all indexed users agree on fourteen resource rows.
struct TNavyOrderResourceDescriptor {
  union {
    int resolveWeightDword;
    struct {
      short resolveWeight; // +0x00 (was g_Resolve_Map_Order_LookupTable_00698108)
      short resolveWeightHighWord;
    };
  };
  union {
    int calculateWeightDword;
    struct {
      short calculateWeight; // +0x04 (was g_Calculate_Mission_Order_LookupTable_0069810C)
      short calculateWeightHighWord;
    };
  };
  short taskForceWeight; // +0x08 (was g_Task_Force_Order_LookupTable_00698110's own +0x00)
  short pad0a;
  short stockCap; // +0x0c (was same table's +0x04); the navy-order normalization base
  short pad0e;
  int navyPriorityWeight; // +0x10 (was g_Navy_Order_Priority_LookupTable_00698118, read as a dword)
  short resourceDescriptorWeightWord0; // +0x14 (was g_ResourceDescriptorWeightWord0Base0069811c)
  short pad16;
  int enabledFlagOrBucketOffset; // +0x18 (was same table's +0x10; low short reused elsewhere
                                 // as a bucket offset, full dword tested for sign as an
                                 // enabled/disabled gate)
  short descriptorWeight;        // +0x1c (was DAT_00698124)
  short pad1e;
  // Per-order-type priority tier used by TNavyMgr::ResolveStrategicBattle's
  // candidate-tier scan/scoring loop (was DAT_00698128).
  short priorityTier; // +0x20
  short pad22;
};
ASSERT_SIZE(TNavyOrderResourceDescriptor, 0x24);
// 0x54fd50: rebuilds g_aCategoryMetricBaselineAverage from the enabled resource types'
// descriptor blends (rounded average across enabled types 1..13).
void RecomputeGlobalCapabilityAverages(void);

// Class-id -> capability-slot lookup table (0x698120, 14 entries, only the leading
// classId field is read by GetEnabledIndustryCapabilitySlotByClass; the remaining 8
// ints of each 0x24-byte record are unmapped (raw, preserved for byte-exact datacmp)).
// Index 0 (classId -1) is never actually reached by that scan (see the function body).
struct IndustryCapabilityClassSlotEntry {
  int classId;
  int raw[8];
};

short GetResourceTypeRandomDrawBlockFlag(short resourceType);
short GetResourceDescriptorWord0CByType(short resourceType);
short GetResourceDescriptorWord10ByType(short resourceType);
short GetResourceDescriptorWord14ByType(short resourceType);
short GetResourceDescriptorWord18ByType(short resourceType);
short GetResourceDescriptorWeightWord1ByType(short resourceType);
short GetResourceDescriptorWord20ByType(short resourceType);
short GetResourceDescriptorWord08ByTypeOffset(short resourceType, short subslot);

// Formats "<count><sep><commodity name>" into `out` (defined in TNavyMgr.cpp; see
// there for the full field note). commodityCode selects the localized name;
// count < 0 suppresses the numeric prefix entirely.
void FormatLocalizedCommodityCountLabelByIndex(CString* out, unsigned int commodityCode,
                                               short count);

// TMilitaryUnit exposes the listing-backed instance and static accessors over
// these tables; their declarations live on the owning class.
// 0x54fee0: g_aCategoryMetricBaselineAverage[index] (returns the int metric, not a pointer
// despite Ghidra's placeholder name).
int GetNavyContextPointerFromGlobalTableByIndex(int index);

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. The foreign-minister tables have eight entries;
// the defense-minister tables have six. Used by TGreatPower vtable slots 0x88-0x8c.

// ============================================================================
// Diplomacy globals
// ============================================================================

class TApplication;
class TAmbitApplication;
class TTacticalBattle;
class ImperialismApp;
// Requires the TacticalTileHeuristicScorerFn typedef from game/TArmyPlayer.h at the
// point of use; declared here per the one-home-for-globals rule.
class TArmyPlayer;
struct AiCityActionCostProfile {
  short primaryMetricCode;
  short primaryMetricMultiplier;
  short secondaryMetricCode;
  short secondaryMetricMultiplier;
  short baseCost;
  short contextBiasSelector;
  short actionId;
};
ASSERT_SIZE(AiCityActionCostProfile, 14);

// ============================================================================
// McAppUI globals
// ============================================================================

// ============================================================================
// UI runtime globals
// ============================================================================

int SetGlobalUiInvalidationFlagAndReturnPrevious(int newValue);
// Clear g_McAppUiActiveFlag_006950AC and return the previous value (0x489a90).
int ClearGlobalUiInvalidationFlagAndReturnPrevious();

// Read g_McAppUiActiveFlag_006950AC (0x489a70) — guard checked before any real painting.
int GetMcAppUiActiveFlag();

// ============================================================================
// bd cwa: globals that were locally re-declared via raw extern in a consumer
// .cpp instead of being declared here (see AGENTS.md's global_data_tables.h
// consolidation rule). Grouped by consumer cluster below.
// ============================================================================

// Per-nation-variant mapped flavor-text table (mapped_flavor_text.cpp / global_data_tables.cpp).
struct MappedFlavorTextNationVariantEntry {
  short variantIndex;
  short pad;
};

// UMapper coastline/region overlay tables (defined in global_data_tables.cpp): the
// per-tile-edge Seapoint quad table and the region-border SeaSegment table the merge pass
// consumes. Forward-declared so this header need not pull in sea_geometry.h; consumers that
// use the tables include it themselves.
class SeapointStretch;
class SeaSegmentStretch;
