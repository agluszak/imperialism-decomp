// TCivDescription wrapper class pair extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TCivDescription.h"
#include "game/TCountry.h"
#include "game/CString.h"
#include "game/TCivUnit.h"
#include "game/TAmbitApplication.h"
#include "game/TGlobalMapState.h"
#include "game/TMacViewMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TView.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

#include <string.h>

namespace {
const unsigned int kAddrTargetTileProfileByCivilianClassAndSlot = 0x00698F58;
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
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

// FUNCTION: IMPERIALISM 0x0044a770
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
void TCivDescription::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point,
                                                           TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;
  int candidateOrdinal = 0;
  int provinceCount;
  int provinceOrdinal;
  int provinceId;
  int provinceTileCount;
  int provinceTileOrdinal;
  short tileIndex;
  RECT* legendRect = &this->legendRects[0];
  unsigned short* currentLegendSelectionCounter = g_awCivilianLegendSelectionCountsBySlot;
  int slotIndex = 0;

  do {
    if (PtInRect(legendRect, point) != 0) {
      TLongintList* ownerNationProvinceCollection =
          g_apTerrainTypeDescriptorTable[this->ownerNationId]->ownedRegionList;
      provinceCount = ownerNationProvinceCollection->GetSize();
      if (0 < provinceCount) {
        provinceOrdinal = 1;
        do {
          provinceId = ownerNationProvinceCollection->At(provinceOrdinal);
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
                  TMapUberPicture* activeMapPicture =
                      static_cast<TMapUberPicture*>(g_pGlobalUiRootController->edgeScrollTarget48);
                  if (activeMapPicture != 0) {
                    activeMapPicture->CenterOn(tileIndex);
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
          provinceCount = ownerNationProvinceCollection->GetSize();
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
  TLongintList* ownerNationProvinceCollection;
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
  provinceCount = ownerNationProvinceCollection->GetSize();
  if (provinceCount < provinceOrdinal) {
    return;
  }
  do {
    int provinceRecordId = ownerNationProvinceCollection->At(provinceOrdinal);
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
    provinceCount = ownerNationProvinceCollection->GetSize();
  } while (provinceOrdinal <= provinceCount);
}

// FUNCTION: IMPERIALISM 0x0058f550
void TCivDescription::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  // ORIG_CALLCONV: __thiscall
  unsigned short* legendSelectionCountsBySlot;
  int stylePrimary;
  int styleSecondary;
  CString localizedTextRef;
  short selectedClass;
  short textWidth;
  short textOriginX;

  if (this->legendInitialized == 0) {
    legendSelectionCountsBySlot = g_awCivilianLegendSelectionCountsBySlot;
    RECT* legendRect = &this->legendRects[0];
    RECT zeroRect = {0, 0, 0, 0};
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
    this->DrawProspector(rectBuffer);
  } else if (selectedClass == kCivilianClass_Engineer) {
    this->DrawEngineer(rectBuffer);
  } else if (selectedClass != kCivilianClass_Developer) {
    this->DrawDeveloper(rectBuffer);
  }

  this->legendInitialized = 1;
  if (selectedClass != (short)-1) {
    stylePrimary = 0;
    styleSecondary = 0;

    // Original calls 0x5c4470 (three-arg apply), then reads the class name via the
    // TSimMgr GetString virtual, and passes each mapped color to 0x4950a0 — the
    // previous port dropped both color arguments.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
    MapUiThemeCodeToStyleFlags(0x2b6c, &stylePrimary);
    MapUiThemeCodeToStyleFlags(0x2b67, &styleSecondary);
    g_pSimMgr->GetString(0x2718, selectedClass, &localizedTextRef);

    textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&localizedTextRef);
    textOriginX = static_cast<short>((this->frameWidth34 / 2) - (textWidth / 2));

    SetQuickDrawColorAndSyncGlobals(styleSecondary);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textOriginX + 1), 0x47);
    DrawTextWithCachedQuickDrawStyleState(&localizedTextRef);
    SetQuickDrawColorAndSyncGlobals(stylePrimary);
    SetQuickDrawTextOriginWithContextOffset(textOriginX, 0x46);
    DrawTextWithCachedQuickDrawStyleState(&localizedTextRef);
  }
}

// FUNCTION: IMPERIALISM 0x0058f7b0
void TCivDescription::DrawEngineer(RECT* boundsBuffer) {
  (void)boundsBuffer;

  CString labelText;
  CString costText;

  // The Mac Civ-toolbar strings identify this block as the Engineer's "Can Build"
  // legend: Depot, Port, Fort, then the terrain types that are still unavailable.
  unsigned char cannotBuildTerrain[4];
  cannotBuildTerrain[0] =
      g_pCityOrderCapabilityState->orderCapRows277[g_pSimMgr->GetActiveNationId()]
          .techStatusByTechId[6] != 2;
  cannotBuildTerrain[1] =
      g_pCityOrderCapabilityState->orderCapRows277[g_pSimMgr->GetActiveNationId()]
          .techStatusByTechId[12] != 2;
  cannotBuildTerrain[2] =
      g_pCityOrderCapabilityState->orderCapRows277[g_pSimMgr->GetActiveNationId()]
          .techStatusByTechId[12] != 2;
  cannotBuildTerrain[3] =
      g_pCityOrderCapabilityState->orderCapRows277[g_pSimMgr->GetActiveNationId()]
          .techStatusByTechId[23] != 2;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 10, 0x2b6c, 3);

  g_pSimMgr->GetString(0x272d, 6, &labelText); // Can Build
  SetQuickDrawTextOriginWithContextOffset(12, 96);
  DrawTextWithCachedQuickDrawStyleState(&labelText);

  g_pSimMgr->GetString(0x272d, 7, &labelText); // Depot
  SetQuickDrawTextOriginWithContextOffset(40, 120);
  DrawTextWithCachedQuickDrawStyleState(&labelText);
  g_pSimMgr->NumToCurrency(2000, &costText);
  SetQuickDrawTextOriginWithContextOffset(84, 120);
  DrawTextWithCachedQuickDrawStyleState(&costText);

  g_pSimMgr->GetString(0x272d, 8, &labelText); // Port
  g_pSimMgr->NumToCurrency(3000, &costText);
  SetQuickDrawTextOriginWithContextOffset(40, 144);
  DrawTextWithCachedQuickDrawStyleState(&labelText);
  SetQuickDrawTextOriginWithContextOffset(84, 144);
  DrawTextWithCachedQuickDrawStyleState(&costText);

  g_pSimMgr->GetString(0x272d, 9, &labelText); // Fort
  g_pSimMgr->NumToCurrency(5000, &costText);
  SetQuickDrawTextOriginWithContextOffset(40, 168);
  DrawTextWithCachedQuickDrawStyleState(&labelText);
  SetQuickDrawTextOriginWithContextOffset(84, 168);
  DrawTextWithCachedQuickDrawStyleState(&costText);

  g_pSimMgr->GetString(0x272d, 10, &labelText); // Cannot Build In
  short titleWidth = MeasureTextExtentWithCachedQuickDrawStyle(&labelText);
  SetQuickDrawTextOriginWithContextOffset(
      static_cast<short>(this->frameWidth34 / 2 - titleWidth / 2), 212);
  DrawTextWithCachedQuickDrawStyleState(&labelText);

  UpdatePaletteIndexWithDefaultFallback(0x10);
  TQuickDrawBlitSurface* iconAtlas = g_pStrategicMapViewSystem->atlas694[1]->GetBlitSurface();
  TQuickDrawBlitSurface* destination = g_pActiveQuickDrawSurfaceContext->GetBlitSurface();

  RECT sourceRect = {347, 0, 374, 20};
  RECT destinationRect = {10, 110, 37, 130};
  SetQuickDrawFillColor(0);
  BlitRectWithOptionalTransparency(iconAtlas, destination, &sourceRect, &destinationRect, 0x24, 0);

  sourceRect.left = 374;
  sourceRect.right = 401;
  destinationRect.top = 134;
  destinationRect.bottom = 154;
  SetQuickDrawFillColor(0);
  BlitRectWithOptionalTransparency(iconAtlas, destination, &sourceRect, &destinationRect, 0x24, 0);

  sourceRect.left = 320;
  sourceRect.right = 347;
  destinationRect.top = 158;
  destinationRect.bottom = 178;
  SetQuickDrawFillColor(0);
  BlitRectWithOptionalTransparency(iconAtlas, destination, &sourceRect, &destinationRect, 0x24, 0);

  SetQuickDrawStrokeColor(0xffffff);
  short terrainIconIndex[4] = {10, 7, 8, 9};
  short iconX = 10;
  short iconY = 216;
  int slot = 0;
  do {
    if (cannotBuildTerrain[slot] != 0) {
      sourceRect.left = terrainIconIndex[slot] * 20;
      sourceRect.top = 0;
      sourceRect.right = sourceRect.left + 20;
      sourceRect.bottom = 20;
      destinationRect.left = iconX;
      destinationRect.top = iconY;
      destinationRect.right = iconX + 20;
      destinationRect.bottom = iconY + 20;

      SetQuickDrawFillColor(0);
      BlitRectWithOptionalTransparency(iconAtlas, destination, &sourceRect, &destinationRect, 0, 0);

      if (iconX < 94) {
        iconX = static_cast<short>(iconX + 28);
      } else {
        iconX = 10;
        iconY = static_cast<short>(iconY + 22);
      }
    }
    slot++;
  } while (slot < 4);
}

// FUNCTION: IMPERIALISM 0x0058fec0
void TCivDescription::DrawProspector(RECT* bounds) {
  (void)bounds;
}

// FUNCTION: IMPERIALISM 0x005903c0
void TCivDescription::DrawDeveloper(RECT* bounds) {
  (void)bounds;
}

TCivDescription::~TCivDescription() {}
