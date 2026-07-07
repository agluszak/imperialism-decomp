// TCivDescription wrapper class pair extracted from Ghidra autogen.

#include <new>

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TCivDescription.h"
#include "game/TCountry.h"
#include <string.h>
#include "game/TCivUnit.h"
#include "game/TGlobalMapState.h"
#include "game/TView.h"
#include "game/CString.h"

#include "game/CString.h"
#include "game/mfc.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

namespace {
const unsigned int kAddrTargetTileProfileByCivilianClassAndSlot = 0x00698F58;
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrGlobalUiRootController = 0x006A1344;
const unsigned int kAddrLocalizationTable = 0x006A20F8;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kAddrCivilianLegendSelectionCountsBySlot = 0x006A4490;

typedef TCivDescription CivDescriptionState;

enum ECivilianClassId {
  kCivilianClass_Miner = 0,
  kCivilianClass_Prospector = 1,
  kCivilianClass_Farmer = 2,
  kCivilianClass_Forester = 3,
  kCivilianClass_Engineer = 4,
  kCivilianClass_Rancher = 5,
  kCivilianClass_Developer = 7,
  kCivilianClass_Driller = 8,
};

struct CivilianClassCacheContext {
  void* vftable;
  unsigned char pad_04_to_83[0x80];
  short selectedCivilianClass;
  short ownerNationId;
  short targetTileCountsBySlot[5];
  unsigned char pad_6e_to_6f[0x02];
};

typedef void(__fastcall* UiRootOnLegendTileSelectedFn)(void* thisLegendSelectionOwner,
                                                       int unusedEdx, int tileIndex);
typedef void(__cdecl* LocalizationFormatFn)(int tokenId, int arg, void* outTextRef);

} // namespace

// The ordinary destructor and the scalar deleting destructor below are both
// compiler-generated (implicit) from real inheritance — never hand-written. The real
// 30-byte body is at 0x0044a7a0; 0x00407f4a is its 5-byte ILT jmp thunk (the vtable slot
// target), handled markerless via config/function_ownership.csv (name_paired_no_marker)
// like the other ILT compiler symbols — no explicit hand-marker on the ILT slot.

// SYNTHETIC: IMPERIALISM 0x0044a7a0
// TCivDescription::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x0058f050
// TCivDescription::CreateObject

TCivDescription::TCivDescription() : TView() {
  selectedCivilianClass = -1;
  legendInitialized = 0;
}
// SYNTHETIC: IMPERIALISM 0x0058f0f0
// TCivDescription::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivDescription, TView)

/* Caches civilian class changes and refreshes target tile counts for supported civilian classes. */

// FUNCTION: IMPERIALISM 0x0058f110
void TCivDescription::UpdateCivilianOrderClassAndRefreshTargetCounts(TCivUnit* orderState) {
  TCivDescription* context = this;
  // ORIG_CALLCONV: __thiscall
  short civilianClassId;
  if (orderState == 0) {
    context->selectedCivilianClass = (short)-1;
    return;
  }
  civilianClassId = orderState->orderType;
  if (civilianClassId != context->selectedCivilianClass) {
    context->selectedCivilianClass = civilianClassId;
    switch ((ECivilianClassId)civilianClassId) {
    case kCivilianClass_Miner:
    case kCivilianClass_Prospector:
    case kCivilianClass_Farmer:
    case kCivilianClass_Forester:
    case kCivilianClass_Rancher:
    case kCivilianClass_Developer:
    case kCivilianClass_Driller:
      context->legendInitialized = 0;
      context->UpdateCivilianOrderTargetTileCountsForOwnerNation(orderState);
      break;
    }
    context->RefreshControl();
  }
}

/* Computes per-class target-tile availability counters for the selected civilian's owner nation.
   Algorithm:
   1. Resolve owner nation from selected civilian tile entry (tile owner byte).
   2. Store owner nation id in command-panel context (+0x62).
   3. Zero five target counters in panel context (+0x64..+0x6C).
   4. Iterate owner-nation province list and each province tile index.
   5. For valid non-blocked tiles (tile+0x0E == 0), read tile profile id (tile+0x13).
   6. Compare profile against 5-entry row in g_anTargetTileProfileByCivilianClassAndSlot selected by
   panel civilian class (+0x60).
   7. Increment matching bucket counters.
   Parameters:
   - pCivilianOrderEntry: selected civilian order/state entry.
   Returns:
   - void.
   Notes:
   - Output counters feed civilian command-panel availability UI/hints.

   ECivilianClassId enum anchor: 0 Miner, 1 Prospector, 2 Farmer, 3 Forester, 4 Engineer, 5 Rancher,
   7 Developer, 8 Driller.

   Consumes pCivilianOrderState->currentTileIndex and class-indexed target profile table. */

/* Handles civ-description click hit-test and selects matching terrain/entry descriptor. */

// FUNCTION: IMPERIALISM 0x0058f1a0
void TCivDescription::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                           int arg4) {
  (void)arg2;
  (void)arg3;
  (void)arg4;
  int candidateOrdinal = 0;
  int provinceCount;
  int provinceOrdinal;
  int provinceId;
  int provinceTileCount;
  int provinceTileOrdinal;
  short tileIndex;
  Rect32* legendRect = &this->legendRects[0];
  unsigned short* currentLegendSelectionCounter = g_awCivilianLegendSelectionCountsBySlot;
  int slotIndex = 0;

  do {
    if (PtInRect(reinterpret_cast<const RECT*>(legendRect), *reinterpret_cast<POINT*>(point)) !=
        0) {
      TSortedList* ownerNationProvinceCollection =
          g_apTerrainTypeDescriptorTable[this->ownerNationId]->ownedRegionList;
      provinceCount = ownerNationProvinceCollection->GetCount();
      if (0 < provinceCount) {
        provinceOrdinal = 1;
        do {
          provinceId = ownerNationProvinceCollection->GetIntByOrdinal(provinceOrdinal);
          provinceTileCount =
              (int)*(char*)(reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) +
                            provinceId * 0xa8 + 0x3a);
          if (0 < provinceTileCount) {
            short* provinceTileIndices = reinterpret_cast<short*>(
                reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + provinceId * 0xa8 +
                0x42);
            provinceTileOrdinal = 0;
            while (provinceTileOrdinal < provinceTileCount) {
              tileIndex = *provinceTileIndices;
              if ((*(char*)(reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) +
                            tileIndex * 0x24 + 0xe) == '\0') &&
                  ((unsigned short)(unsigned char)*(
                       char*)(reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) +
                              tileIndex * 0x24 + 0x13) == (unsigned short)slotIndex)) {
                if ((int)(unsigned int)(*currentLegendSelectionCounter) <= candidateOrdinal) {
                  void* uiRootController = *reinterpret_cast<void**>(kAddrGlobalUiRootController);
                  void* legendSelectionOwner =
                      *reinterpret_cast<void**>(reinterpret_cast<char*>(uiRootController) + 0x48);
                  if (legendSelectionOwner != 0) {
                    reinterpret_cast<UiRootOnLegendTileSelectedFn>(reinterpret_cast<int*>(
                        *reinterpret_cast<void**>(legendSelectionOwner))[0x78])(
                        legendSelectionOwner, 0, (int)tileIndex);
                  }
                  *currentLegendSelectionCounter =
                      (unsigned short)((unsigned int)(*currentLegendSelectionCounter) + 1);
                  return;
                }
                candidateOrdinal = candidateOrdinal + 1;
              }
              provinceTileOrdinal = provinceTileOrdinal + 1;
              provinceTileIndices = provinceTileIndices + 1;
            }
          }
          provinceOrdinal = provinceOrdinal + 1;
          provinceCount = ownerNationProvinceCollection->GetCount();
        } while (provinceOrdinal <= provinceCount);
      }
    }
    currentLegendSelectionCounter = currentLegendSelectionCounter + 1;
    slotIndex = slotIndex + 1;
    legendRect = legendRect + 1;
    if (g_pActiveCityDialogLegendSelectionOwner <= currentLegendSelectionCounter) {
      return;
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x0058f3c0
void TCivDescription::UpdateCivilianOrderTargetTileCountsForOwnerNation(TCivUnit* orderState) {
  TCivDescription* context = this;
  // ORIG_CALLCONV: __thiscall
  short ownerNationId;
  int provinceTileOrdinal;
  char* provinceRecord;
  short* targetCountSlot;
  int classSlotOrdinal;
  int remainingSlots;
  int provinceOrdinal;
  short* provinceTileIndices;
  int provinceTileIndex;
  char* tableBase;
  short tileProfileId;
  TSortedList* ownerNationProvinceCollection;
  int provinceCount;

  provinceOrdinal = 1;
  ownerNationId = (short)*(char*)(reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) +
                                  4 + orderState->tileIndex06 * 0x24);
  context->ownerNationId = ownerNationId;
  ownerNationProvinceCollection = g_apTerrainTypeDescriptorTable[ownerNationId]->ownedRegionList;
  context->targetTileCountsBySlot[4] = 0;
  context->targetTileCountsBySlot[3] = 0;
  context->targetTileCountsBySlot[2] = 0;
  context->targetTileCountsBySlot[1] = 0;
  context->targetTileCountsBySlot[0] = 0;
  provinceCount = ownerNationProvinceCollection->GetCount();
  if (provinceCount < provinceOrdinal) {
    return;
  }
  do {
    int provinceRecordId = ownerNationProvinceCollection->GetIntByOrdinal(provinceOrdinal);
    provinceTileOrdinal = 0;
    provinceRecord =
        reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + provinceRecordId * 0xa8;
    if ('\0' < *(char*)(provinceRecord + 0x3a)) {
      provinceTileIndices = reinterpret_cast<short*>(provinceRecord + 0x42);
      do {
        provinceTileIndex = (short)*provinceTileIndices;
        tableBase = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) +
                    (int)(short)provinceTileIndex * 0x24;
        if (*(char*)(tableBase + 0xe) == '\0') {
          tileProfileId = (short)*(char*)(tableBase + 0x13);
          classSlotOrdinal = 0;
          remainingSlots = 5;
          targetCountSlot = &context->targetTileCountsBySlot[0];
          do {
            if (tileProfileId ==
                g_anTargetTileProfileByCivilianClassAndSlot[classSlotOrdinal +
                                                            context->selectedCivilianClass * 5]) {
              *targetCountSlot = (short)(*targetCountSlot + 1);
            }
            classSlotOrdinal = classSlotOrdinal + 1;
            targetCountSlot = targetCountSlot + 1;
            remainingSlots = remainingSlots - 1;
          } while (remainingSlots != 0);
        }
        provinceTileOrdinal = provinceTileOrdinal + 1;
        provinceTileIndices = provinceTileIndices + 1;
      } while (provinceTileOrdinal < *(char*)(provinceRecord + 0x3a));
    }
    provinceOrdinal = provinceOrdinal + 1;
    provinceCount = ownerNationProvinceCollection->GetCount();
  } while (provinceOrdinal <= provinceCount);
}

// FUNCTION: IMPERIALISM 0x0058f550
void TCivDescription::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  // ORIG_CALLCONV: __thiscall
  int slotIndex;
  unsigned short* legendSelectionCountsBySlot;
  int stylePrimary;
  int styleSecondary;
  CString localizedTextRef;
  short selectedClass;
  short textWidth;
  short textOriginX;

  if (this->legendInitialized == 0) {
    legendSelectionCountsBySlot = g_awCivilianLegendSelectionCountsBySlot;
    Rect32* legendRect = &this->legendRects[0];
    Rect32 zeroRect = {0, 0, 0, 0};
    do {
      *legendRect = zeroRect;
      legendRect++;
      *legendSelectionCountsBySlot = 0;
      legendSelectionCountsBySlot++;
    } while (legendSelectionCountsBySlot < g_pActiveCityDialogLegendSelectionOwner);
    this->field04 = 0;
  }

  selectedClass = this->selectedCivilianClass;
  if (selectedClass == kCivilianClass_Prospector) {
    this->DispatchPictureResourceCommand(0, 0, 0, 0, 0);
  } else if (selectedClass == kCivilianClass_Engineer) {
    RECT boundsBuffer;
    this->BuildInsetContentRect(&boundsBuffer);
  } else if (selectedClass != kCivilianClass_Developer) {
    this->AssertCityProductionGlobalStateInitialized(0, 0);
  }

  this->legendInitialized = 1;
  if (selectedClass != (short)-1) {
    stylePrimary = 0;
    styleSecondary = 0;

    // Original calls 0x5c4470 (three-arg apply), then reads the class name via the
    // TSimMgr GetString virtual, and passes each mapped color to 0x4950a0 — the
    // previous port dropped both color arguments.
    ApplyUiTextStyleAndSyncColor(0, 0xc, 0x2b68);
    MapUiThemeCodeToStyleFlags(0x2b6c, &stylePrimary);
    MapUiThemeCodeToStyleFlags(0x2b67, &styleSecondary);
    g_pSimMgr->GetString(0x2718, selectedClass, &localizedTextRef);

    textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&localizedTextRef);
    textOriginX = static_cast<short>((this->field34 / 2) - (textWidth / 2));

    SetQuickDrawColorAndSyncGlobals(styleSecondary);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textOriginX + 1), 0x47);
    DrawTextWithCachedStyle(&localizedTextRef);
    SetQuickDrawColorAndSyncGlobals(stylePrimary);
    SetQuickDrawTextOriginWithContextOffset(textOriginX, 0x46);
    DrawTextWithCachedStyle(&localizedTextRef);
  }
}

// TODO(bd follow-up): real body (Ghidra name RenderCivilianTargetLegendVariantA, 1438
// bytes) draws the Engineer target-tile legend into legendRects[16] (icon rects +
// class-name label via g_pSimMgr->GetString), ignoring boundsBuffer. Unported — the
// Engineer civilian legend overlay currently never paints. See bd tracking issue.
// FUNCTION: IMPERIALISM 0x0058f7b0
void TCivDescription::BuildInsetContentRect(RECT* boundsBuffer) {
  (void)boundsBuffer;
}

// FUNCTION: IMPERIALISM 0x0058fec0
void TCivDescription::DispatchPictureResourceCommand(int eventType, void* eventSender,
                                                     void* eventDataA, void* eventDataB,
                                                     int commandFlag) {
  (void)commandFlag;
  (void)eventType;
  (void)eventSender;
  (void)eventDataA;
  (void)eventDataB;
}

// FUNCTION: IMPERIALISM 0x005903c0
void TCivDescription::AssertCityProductionGlobalStateInitialized(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

TCivDescription::~TCivDescription() {}
