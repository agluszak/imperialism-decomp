#pragma once

// Transitional declarations shared by subsystem global headers. Definitions and address
// markers live in src/game/core/global_data_tables.cpp.

#include "game/ui_screens/CString.h"

// Each symbol has exactly one reccmp GLOBAL marker in the defining translation unit.

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
int GetTradeSummarySelectionTagByIndex(short index);

struct NationState;
struct TextStyle;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceContextDescriptor;
struct TCdAudioDevice;
struct CRGBColor;
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
class TD0TemplateDialog;
class CDib;

struct GlobalViewportRectDefaultsRecord {
  int field0;
  RECT viewportBounds;
};

// LAYOUT: fourteen per-resource navy-order descriptors at 0x00698108 with stride 0x24.
// The shipyard indexes all nine dword columns dynamically. Gameplay readers give the low
// signed word of each column its domain meaning; the ranking code reads columns 0, 1, and 4
// as full dwords. Keep one physical array model rather than overlapping named and indexed views.
struct TNavyOrderResourceDescriptor {
  enum Column {
    kResolveWeight = 0,
    kCalculateWeight = 1,
    kTaskForceWeight = 2,
    kStockCap = 3,
    kNavyPriorityWeight = 4,
    kResourceDescriptorWeightWord0 = 5,
    kToolbarBucketIndex = 6,
    kDescriptorWeight = 7,
    kPriorityTier = 8,
    kColumnCount = 9
  };

  int valueByColumn[kColumnCount];

  __inline int ResolveWeightDword() const {
    return valueByColumn[kResolveWeight];
  }
  __inline short ResolveWeight() const {
    return static_cast<short>(valueByColumn[kResolveWeight]);
  }
  __inline int CalculateWeightDword() const {
    return valueByColumn[kCalculateWeight];
  }
  __inline short CalculateWeight() const {
    return static_cast<short>(valueByColumn[kCalculateWeight]);
  }
  __inline short TaskForceWeight() const {
    return static_cast<short>(valueByColumn[kTaskForceWeight]);
  }
  __inline short StockCap() const {
    return static_cast<short>(valueByColumn[kStockCap]);
  }
  __inline int NavyPriorityWeightDword() const {
    return valueByColumn[kNavyPriorityWeight];
  }
  __inline short NavyPriorityWeight() const {
    return static_cast<short>(valueByColumn[kNavyPriorityWeight]);
  }
  __inline short ResourceDescriptorWeightWord0() const {
    return static_cast<short>(valueByColumn[kResourceDescriptorWeightWord0]);
  }
  __inline int ToolbarBucketIndexDword() const {
    return valueByColumn[kToolbarBucketIndex];
  }
  __inline short ToolbarBucketIndex() const {
    return static_cast<short>(valueByColumn[kToolbarBucketIndex]);
  }
  __inline short DescriptorWeight() const {
    return static_cast<short>(valueByColumn[kDescriptorWeight]);
  }
  __inline short PriorityTier() const {
    return static_cast<short>(valueByColumn[kPriorityTier]);
  }
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
short GetResourceDescriptorStatByColumn(short resourceType, short statColumn);

// Formats "<count><sep><commodity name>" into `out` (defined in TNavyMgr.cpp; see
// there for the full field note). commodityCode selects the localized name;
// count < 0 suppresses the numeric prefix entirely.
void FormatLocalizedCommodityCountLabelByIndex(CString* out, unsigned int commodityCode,
                                               short count);

// TMilitaryUnit exposes the listing-backed instance and static accessors over
// these tables; their declarations live on the owning class.
// Returns the precomputed baseline for one navy-order category. 0x54fee0.
int GetNavyOrderCategoryBaseline(int category);

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
// Cross-consumer globals grouped by their current consumer cluster.
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
