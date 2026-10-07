
#include "decomp_types.h"
#include "game/ui_widgets/TCivDescription.h"
#include "game/city_ui/TCountry.h"
#include "game/core/CString.h"
#include "game/military/TCivUnit.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/mfc.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

#include <string.h>

namespace {
const unsigned int kAddrTargetTileProfileByCivilianClassAndSlot = 0x00698F58;
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrLocalizationTable = 0x006A20F8;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kAddrCivilianLegendSelectionCountsBySlot = 0x006A4490;

struct CivilianClassCacheContext {
  void* vftable;
  unsigned char pad_04_to_83[0x80];
  CivilianUnitKindStorage selectedCivilianClass;
  NationSlot ownerNationId;
  short targetTileCountsBySlot[5];
  unsigned char pad_6e_to_6f[0x02];
};

typedef void(__cdecl* LocalizationFormatFn)(int tokenId, int arg, void* outTextRef);

} // namespace

// FUNCTION: IMPERIALISM 0x0044a770
TCivDescription::TCivDescription() : TView() {
  selectedCivilianClass = -1;
  targetTileCountsBySlot[4] = 0;
}

// FUNCTION: IMPERIALISM 0x0044a7d0
TCivDescription::~TCivDescription() {}

IMPLEMENT_DYNCREATE(TCivDescription, TView)

/* Caches civilian class changes and refreshes target tile counts for supported civilian classes. */

// FUNCTION: IMPERIALISM 0x0058f110
void TCivDescription::UpdateCivilianOrderClassAndRefreshTargetCounts(TCivUnit* orderState) {
  TCivDescription* context = this;
  // ORIG_CALLCONV: __thiscall
  CivilianUnitKindStorage civilianClassId;
  if (orderState == 0) {
    context->selectedCivilianClass = (short)-1;
    return;
  }
  civilianClassId = orderState->orderType;
  if (civilianClassId != context->selectedCivilianClass) {
    context->selectedCivilianClass = civilianClassId;
    switch (DecodeCivilianUnitKind(civilianClassId)) {
    case kCivilianUnitMiner:
    case kCivilianUnitProspector:
    case kCivilianUnitFarmer:
    case kCivilianUnitForester:
    case kCivilianUnitRancher:
    case kCivilianUnitDeveloper:
    case kCivilianUnitDriller:
      context->targetTileCountsBySlot[4] = 0;
      context->CountWorkableSpaces(orderState);
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

   CivilianUnitKind is the canonical 0..8 civilian class vocabulary.

   Consumes pCivilianOrderState->currentTileIndex and class-indexed target profile table. */

/* Handles civ-description click hit-test and selects matching terrain/entry descriptor. */

// FUNCTION: IMPERIALISM 0x0058f1a0
void TCivDescription::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
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
      do {
        candidateOrdinal = 0;
        TLongintList* ownerNationProvinceCollection =
            g_apTerrainTypeDescriptorTable[this->ownerNationId]->ownedRegionList;
        provinceCount = ownerNationProvinceCollection->GetSize();
        if (provinceCount > 0) {
          provinceOrdinal = 1;
          do {
            provinceId = ownerNationProvinceCollection->At(provinceOrdinal);
            Province* province = &g_pGlobalMapState->cityScoreTable[provinceId];
            provinceTileCount = province->linkedRegionCount;
            if (provinceTileCount > 0) {
              short* provinceTileIndices = province->linkedTileIndices;
              provinceTileOrdinal = 0;
              while (provinceTileOrdinal < provinceTileCount) {
                tileIndex = *provinceTileIndices;
                TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
                if ((tile->recruitSearchVisited == 0) &&
                    ((unsigned short)(unsigned char)tile->gateFlag == (unsigned short)slotIndex)) {
                  if ((int)(unsigned int)(*currentLegendSelectionCounter) <= candidateOrdinal) {
                    TMapUberPicture* activeMapPicture =
                        static_cast<TMapUberPicture*>(g_pAmbitApplication->edgeScrollTarget);
                    if (activeMapPicture != 0) {
                      activeMapPicture->CenterOn(tileIndex);
                    }
                    *currentLegendSelectionCounter =
                        (unsigned short)((unsigned int)(*currentLegendSelectionCounter) + 1);
                    return;
                  }
                  ++candidateOrdinal;
                }
                ++provinceTileOrdinal;
                ++provinceTileIndices;
              }
            }
            ++provinceOrdinal;
            provinceCount = ownerNationProvinceCollection->GetSize();
          } while (provinceOrdinal <= provinceCount);
        }
        if (candidateOrdinal > 0) {
          *currentLegendSelectionCounter =
              (unsigned short)((unsigned int)(*currentLegendSelectionCounter) % candidateOrdinal);
        }
      } while ((candidateOrdinal > 0) &&
               (candidateOrdinal < (int)(unsigned int)(*currentLegendSelectionCounter)));
    }
    ++currentLegendSelectionCounter;
    ++slotIndex;
    ++legendRect;
    if (g_awCivilianLegendSelectionCountsBySlot + 16 <= currentLegendSelectionCounter) {
      return;
    }
  } while (true);
}

#ifdef IMPERIALISM_RUNTIME_TESTS
bool TCivDescription::ActivateLegendSlot(short slotIndex) {
  if (slotIndex < 0 || slotIndex >= 16) {
    return false;
  }
  RECT* legendRect = &legendRects[slotIndex];
  if (legendRect->right <= legendRect->left || legendRect->bottom <= legendRect->top) {
    return false;
  }
  CPoint point((legendRect->left + legendRect->right) / 2,
               (legendRect->top + legendRect->bottom) / 2);
  CPoint origin(0, 0);
  DoMouseCommand(point, 0, origin);
  return true;
}
#endif

// FUNCTION: IMPERIALISM 0x0058f3c0
void TCivDescription::CountWorkableSpaces(TCivUnit* orderState) {
  TCivDescription* context = this;
  // ORIG_CALLCONV: __thiscall
  NationSlot ownerNationId;
  int provinceTileOrdinal;
  Province* provinceRecord;
  short* targetCountSlot;
  int classSlotOrdinal;
  int remainingSlots;
  int provinceOrdinal;
  short* provinceTileIndices;
  int provinceTileIndex;
  TTerrainStateRecord* tileRecord;
  short tileProfileId;
  TLongintList* ownerNationProvinceCollection;
  int provinceCount;

  provinceOrdinal = 1;
  ownerNationId = static_cast<NationSlot>(
      g_pGlobalMapState->terrainStateTable[orderState->tileIndex].ownerNationTag);
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
    provinceRecord = &g_pGlobalMapState->cityScoreTable[provinceRecordId];
    if (provinceRecord->linkedRegionCount > 0) {
      provinceTileIndices = provinceRecord->linkedTileIndices;
      do {
        provinceTileIndex = (short)*provinceTileIndices;
        tileRecord = &g_pGlobalMapState->terrainStateTable[static_cast<short>(provinceTileIndex)];
        if (tileRecord->recruitSearchVisited == 0) {
          tileProfileId = static_cast<short>(tileRecord->gateFlag);
          classSlotOrdinal = 0;
          targetCountSlot = &context->targetTileCountsBySlot[0];
          for (int i = 0; i < 5; ++i) {
            if (tileProfileId ==
                g_anTargetTileProfileByCivilianClassAndSlot[classSlotOrdinal +
                                                            context->selectedCivilianClass * 5]) {
              *targetCountSlot = (short)(*targetCountSlot + 1);
            }
            ++classSlotOrdinal;
            ++targetCountSlot;
          }
        }
        ++provinceTileOrdinal;
        ++provinceTileIndices;
      } while (provinceTileOrdinal < provinceRecord->linkedRegionCount);
    }
    ++provinceOrdinal;
    provinceCount = ownerNationProvinceCollection->GetSize();
  } while (provinceOrdinal <= provinceCount);
}

// FUNCTION: IMPERIALISM 0x0058f550
void TCivDescription::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  // ORIG_CALLCONV: __thiscall
  unsigned short* legendSelectionCountsBySlot;
  COLORREF stylePrimary;
  COLORREF styleSecondary;
  CString localizedTextRef;
  CivilianUnitKindStorage selectedClass;
  short textWidth;
  short textOriginX;

  if (this->targetTileCountsBySlot[4] == 0) {
    legendSelectionCountsBySlot = g_awCivilianLegendSelectionCountsBySlot;
    RECT* legendRect = &this->legendRects[0];
    RECT zeroRect = {0, 0, 0, 0};
    do {
      *legendRect = zeroRect;
      legendRect++;
      *legendSelectionCountsBySlot = 0;
      legendSelectionCountsBySlot++;
    } while (legendSelectionCountsBySlot < g_awCivilianLegendSelectionCountsBySlot + 16);
    this->enabled = 0;
  }

  selectedClass = this->selectedCivilianClass;
  if (selectedClass == EncodeCivilianUnitKind(kCivilianUnitProspector)) {
    this->DrawProspector(rectBuffer);
  } else if (selectedClass == EncodeCivilianUnitKind(kCivilianUnitEngineer)) {
    this->DrawEngineer(rectBuffer);
  } else if (selectedClass != EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
    this->DrawDeveloper(rectBuffer);
  }

  this->targetTileCountsBySlot[4] = 1;
  if (selectedClass != (short)-1) {
    stylePrimary = 0;
    styleSecondary = 0;

    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);
    ResolveUiThemeColor(0x2b6c, &stylePrimary);
    ResolveUiThemeColor(0x2b67, &styleSecondary);
    g_pSimMgr->GetString(0x2718, selectedClass, &localizedTextRef);

    textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&localizedTextRef);
    textOriginX = static_cast<short>((this->frameWidth / 2) - (textWidth / 2));

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

  CString labelText;
  CString costText;

  unsigned char cannotBuildTerrain[4];
  cannotBuildTerrain[0] =
      g_pTechMgr->orderCapRows277[g_pSimMgr->GetPlayerCountry()].techStatusByTechId[6] != 2;
  cannotBuildTerrain[1] =
      g_pTechMgr->orderCapRows277[g_pSimMgr->GetPlayerCountry()].techStatusByTechId[12] != 2;
  cannotBuildTerrain[2] =
      g_pTechMgr->orderCapRows277[g_pSimMgr->GetPlayerCountry()].techStatusByTechId[12] != 2;
  cannotBuildTerrain[3] =
      g_pTechMgr->orderCapRows277[g_pSimMgr->GetPlayerCountry()].techStatusByTechId[23] != 2;

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
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(this->frameWidth / 2 - titleWidth / 2),
                                          212);
  DrawTextWithCachedQuickDrawStyleState(&labelText);

  UpdatePaletteIndexWithDefaultFallback(0x10);
  TQuickDrawBlitSurface* iconAtlas = g_pMacViewMgr->tileOverlayStripWorlds[1]->GetBlitSurface();
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
  for (int slot = 0; slot < 4; ++slot) {
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
  }
}

// FUNCTION: IMPERIALISM 0x0058fec0
void TCivDescription::DrawProspector(RECT* bounds) {

  CString text;
  unsigned long themeColor = 0;

  bool oilUnlocked =
      g_pTechMgr->orderCapRows277[g_pSimMgr->GetPlayerCountry()].techStatusByTechId[4] == 2;

  short columnResourceIcons[5][4] = {
      {3, 4, -1, -1}, {3, 4, 0x16, 0x15}, {6, -1, -1, -1}, {6, -1, -1, -1}, {6, -1, -1, -1}};

  ResolveUiThemeColor(0x2b6c, &themeColor);
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 10, 0x2b6c, 3);

  g_pSimMgr->GetString(0x272d, 5, &text); // Can Find
  SetQuickDrawTextOriginWithContextOffset(5, 96);
  DrawTextWithCachedQuickDrawStyleState(&text);

  int columnCount = oilUnlocked ? 5 : 2;
  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);

  short columnTop = 0x68;
  for (int column = 0; column < columnCount; ++column) {
    short terrainIcon = g_anTargetTileProfileByCivilianClassAndSlot[5 + column];
    RECT sourceRect = {terrainIcon * 20, 0, (terrainIcon + 1) * 20, 20};
    RECT destinationRect = {12, columnTop, 0x20, columnTop + 0x14};
    if (column == 1) {
      destinationRect.top += 0xc;
      destinationRect.bottom += 0xc;
    }
    SetQuickDrawFillColor(0);
    BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[1]->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0, 0);

    if (targetTileCountsBySlot[4] == 0) {
      legendRects[terrainIcon] = destinationRect;
      enabled = 1;
    }

    SetQuickDrawColorAndSyncGlobals(themeColor);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(destinationRect.right + 2),
                                            static_cast<short>(destinationRect.bottom));
    text.Format(g_szDecimalFormat, targetTileCountsBySlot[column]);
    DrawTextWithCachedQuickDrawStyleState(&text);

    UpdatePaletteIndexWithDefaultFallback(0x10);
    SetQuickDrawFillColor(0);

    int firstRowRight = 0x3c;
    int secondRowX = 0;
    for (int slot = 0; slot < 4; ++slot) {
      short resourceIcon = columnResourceIcons[column][slot];
      if (resourceIcon != -1) {
        sourceRect.left = resourceIcon * 20;
        sourceRect.top = 0;
        sourceRect.right = (resourceIcon + 1) * 20;
        sourceRect.bottom = 0x18;
        if (firstRowRight < 0x78) {
          destinationRect.left = firstRowRight - 0x14;
          destinationRect.top = columnTop - 4;
          destinationRect.right = firstRowRight;
          destinationRect.bottom = columnTop + 0x14;
        } else {
          destinationRect.left = secondRowX - 0x18;
          destinationRect.top = columnTop + 0x18;
          destinationRect.right = secondRowX - 4;
          destinationRect.bottom = columnTop + 0x30;
        }
        BlitRectWithOptionalTransparency(g_pMacViewMgr->unitIconAtlas->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &sourceRect, &destinationRect, 0x24, 0);
      }
      firstRowRight += 0x1e;
      secondRowX += 0x20;
    }
    SetQuickDrawStrokeColor(0xffffff);

    columnTop += 0x1c;
    if (column == 1) {
      columnTop += 0x18;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005903c0
void TCivDescription::DrawDeveloper(RECT* bounds) {

  CPoint origin(0, 0);
  WindowToLocal(&origin);
  int originX = origin.x;
  int originY = origin.y;

  short maxRowsByClass[9] = {2, 0, 3, 1, 0, 2, 0, 0, 3};
  // Count-text x anchors, indexed row + 3 * maxRowsByClass[class].
  short rowIconXTable[12] = {0, 0, 0, 0x237, 0, 0, 0x21c, 0x24c, 0, 0x216, 0x237, 0x258};

  CString text;

  short civilianClass = selectedCivilianClass;
  if (g_anDevelopmentIconStripBaseXByCivilianClass[civilianClass] >= 0) {
    // Centered "Development" title.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);
    g_pSimMgr->GetString(0x272d, 1, &text);
    short titleWidth = MeasureTextExtentWithCachedQuickDrawStyle(&text);
    SetQuickDrawTextOriginWithContextOffset(
        static_cast<short>(this->frameWidth / 2 - titleWidth / 2), 0x6a);
    DrawTextWithCachedQuickDrawStyleState(&text);

    short stripBase = g_anDevelopmentIconStripBaseXByCivilianClass[civilianClass];
    int level = 0;
    for (int slot = 0; slot < 4; ++slot) {
      int resourceType = g_anDevelopableResourceTypesByCivilianClass[civilianClass][slot];
      if (resourceType == -1) {
        continue;
      }
      int reached =
          g_pTechMgr
              ->capabilityValueByNationAndResource[g_pSimMgr->GetPlayerCountry()][resourceType] -
          1;
      if (level <= reached) {
        level = reached;
      }
    }

    RECT sourceRect = {stripBase + level * 38, 0, stripBase + level * 38 + 38, 0x1a};
    RECT destinationRect = {this->frameWidth / 2 - 0xb, originY + 0x12c,
                            this->frameWidth / 2 + 0x1b, originY + 0x146};
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(g_pMacViewMgr->unitOverlayAtlas->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destinationRect, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);

    // Centered "Output" title.
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);
    g_pSimMgr->GetString(0x272d, 2, &text);
    titleWidth = MeasureTextExtentWithCachedQuickDrawStyle(&text);
    SetQuickDrawTextOriginWithContextOffset(
        static_cast<short>(this->frameWidth / 2 - titleWidth / 2), 0xa2);
    DrawTextWithCachedQuickDrawStyleState(&text);
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);

    for (int yieldSlot = 0; yieldSlot < 4; ++yieldSlot) {
      short resourceType =
          static_cast<short>(g_anDevelopableResourceTypesByCivilianClass[civilianClass][yieldSlot]);
      if (resourceType == -1) {
        continue;
      }
      sourceRect.left = resourceType * 20;
      sourceRect.top = 0;
      sourceRect.right = (resourceType + 1) * 20;
      sourceRect.bottom = 0x18;
      destinationRect.left = g_aDeveloperYieldIconAnchors[yieldSlot][0] + originX;
      destinationRect.top = originY + g_aDeveloperYieldIconAnchors[yieldSlot][1];
      destinationRect.right = destinationRect.left + 0x14;
      destinationRect.bottom = destinationRect.top + 0x18;
      if (selectedCivilianClass == 3 || selectedCivilianClass == 8) {
        destinationRect.left += 0x1b;
        destinationRect.right += 0x1b;
      }
      UpdatePaletteIndexWithDefaultFallback(0x10);
      BlitRectWithOptionalTransparency(g_pMacViewMgr->unitIconAtlas->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &sourceRect, &destinationRect, 0x24, 0);
      SetQuickDrawStrokeColor(0xffffff);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(destinationRect.right + 4),
                                              static_cast<short>(destinationRect.bottom - 4));
      short capabilityValue =
          g_pTechMgr
              ->capabilityValueByNationAndResource[g_pSimMgr->GetPlayerCountry()][resourceType];
      text.Format(
          g_szDecimalFormat,
          static_cast<int>(g_abUniversityRequirementLevelById[resourceType][capabilityValue]));
      DrawTextWithCachedQuickDrawStyleState(&text);
    }

    short rowLimit = maxRowsByClass[civilianClass];
    if (civilianClass == 2 &&
        g_pTechMgr->capabilityValueByNationAndResource[g_pSimMgr->GetPlayerCountry()][0] == 0) {
      --rowLimit;
    }
    if (rowLimit > 0) {
      short* countPtr = &targetTileCountsBySlot[0];
      for (int row = 0; row < rowLimit; ++row, ++countPtr) {
        short terrainIcon = g_anTargetTileProfileByCivilianClassAndSlot[civilianClass * 5 + row];
        if (terrainIcon == -1) {
          continue;
        }
        sourceRect.left = terrainIcon * 20;
        sourceRect.top = 0;
        sourceRect.right = (terrainIcon + 1) * 20;
        sourceRect.bottom = 0x14;
        short iconX = rowIconXTable[row + 3 * rowLimit];
        destinationRect.bottom = originY + 0x1ba;
        destinationRect.left = iconX + originX;
        destinationRect.top = originY + 0x1a6;
        destinationRect.right = destinationRect.left + 0x14;
        ResetQuickDrawStrokeState();
        SetQuickDrawStrokeColor(0xffffff);
        SetQuickDrawFillColor(0);
        BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[1]->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &sourceRect, &destinationRect, 0, 0);
        if (targetTileCountsBySlot[4] == 0) {
          legendRects[terrainIcon] = destinationRect;
          enabled = 1;
        }
        ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b6c);
        SetQuickDrawTextOriginWithContextOffset(static_cast<short>(originX + iconX + 0x18), 0x100);
        text.Format(g_szDecimalFormat, *countPtr);
        DrawTextWithCachedQuickDrawStyleState(&text);
      }
    }
  }
}
