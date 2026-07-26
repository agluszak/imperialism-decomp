#include <time.h>
#include "game/ui_tags_common.h"

#include "game/ui_screens/TZone.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"

#include <cstdlib>
#include <new>

#include "game/military/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/navy/TAdmiral.h"
#include "game/map/TMapMgr.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/navy/TOcean.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_screens/TPortZone.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"

namespace {

void DeleteUnlinkedZone(TZone* zone) {
  delete zone;
}

static inline int SignedRemainderByFour(int value) {
  return value % 4;
}

static inline short InlineTileIndexFromRowCol(int row, int col) {
  if (row < 0 || row >= 0x3c || col < 0 || col >= 0x6c) {
    return -1;
  }
  return static_cast<short>(col + row * 0x6c);
}

enum { kFirstMapRegionNationTag = 0x17 };

// 0x005e7f50 resolves to CRT `_free` (per symbols.csv), not a game-specific tracking
// helper -- call the real library function directly (LIBRARY: IMPERIALISM 0x005e7f50).
} // namespace

// TEMPLATE: IMPERIALISM 0x00558860
// stretch::operator[]
// SYNTHETIC: IMPERIALISM 0x0055e660
// TZone::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055e6e0
// TZone::GetRuntimeClass

IMPLEMENT_DYNCREATE(TZone, TObject)

// FUNCTION: IMPERIALISM 0x0055e700
TZone::TZone() : displayName(), primaryNeighbors(), secondaryNeighbors() {
  seedNationId12 = -1;
  contextOrdinal14 = static_cast<short>(g_nMapActionContextCount);
  g_nMapActionContextCount = g_nMapActionContextCount + 1;
  tileOrTerrainId0c = -1;
  nationKeyMask10 = 0;
  prev18 = static_cast<TZone*>(g_pMapActionContextListHead);
  next1c = 0;
  distanceLevel44 = 0;
  statusCode04 = -1;
  activeTileIndex20 = -1;
  g_pMapActionContextListHead = this;
  if (prev18 != 0) {
    prev18->next1c = this;
  }
  if (g_pMapActionContextDistanceCache != 0) {
    delete[] static_cast<char*>(g_pMapActionContextDistanceCache);
    g_pMapActionContextDistanceCache = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0055e820
bool TZone::QueryZoneCapabilityFlagA() {
  return true;
}

// FUNCTION: IMPERIALISM 0x0055e840
bool TZone::QueryPortZoneCapability() {
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e860
bool TZone::QueryZoneCapabilityFlagC() {
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e880
bool TZone::QueryZoneCapabilityFlagD(int unused) {
  (void)unused;
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e8a0
bool TZone::QueryZoneCapabilityFlagE(int unused) {
  (void)unused;
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e8c0
bool TZone::HasZoneActiveChildCount(int unused) {
  (void)unused;
  return distanceLevel44 > 0;
}

// FUNCTION: IMPERIALISM 0x0055e8e0
TZone** TZonePrimaryNeighborStretch::Add(TZone* zone) {
  TZone** existing = FindEntry(zone);
  if (existing != 0) {
    return existing;
  }
  return stretch<TZone*>::Add(zone);
}

// FUNCTION: IMPERIALISM 0x0055e9c0
Province** TZoneSecondaryNeighborStretch::Add(Province* entry) {
  Province** existing = FindEntry(entry);
  if (existing != 0) {
    return existing;
  }
  return stretch<Province*>::Add(entry);
}

// TEMPLATE: IMPERIALISM 0x0055ead0
// ?Add@?$stretch@PAVTZone@@@@UAEPAPAVTZone@@PAV2@@Z

// TEMPLATE: IMPERIALISM 0x0055eba0
// ?Add@?$stretch@PAUProvince@@@@UAEPAPAUProvince@@PAU2@@Z

// FUNCTION: IMPERIALISM 0x0055ec60
void TZone::Free() {
  if (g_pMapActionContextListHead == this) {
    g_pMapActionContextListHead = prev18;
  }
  if (prev18 != 0) {
    prev18->next1c = next1c;
  }
  if (next1c != 0) {
    next1c->prev18 = prev18;
  }
  next1c = 0;
  prev18 = 0;
  DeleteUnlinkedZone(this);
}

// FUNCTION: IMPERIALISM 0x0055ed20
void TZone::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadSharedString(&displayName, 0x20);
  stream->ReadBytes(&statusCode04, 2);
  stream->ReadBytes(&tileOrTerrainId0c, 4);
  stream->ReadBytes(&seedNationId12, 2);
  stream->ReadBytes(&activeTileIndex20, 2);
  if (g_nSaveFormatVersion < 0x12) {
    contextOrdinal14 = static_cast<short>(g_nMapActionContextCount);
    ++g_nMapActionContextCount;
  } else {
    stream->ReadBytes(&contextOrdinal14, 2);
  }
  nationKeyMask10 = 0;
  distanceLevel44 = 0;

  if (primaryNeighbors.Data() != 0) {
    free(primaryNeighbors.Detach());
  }
  if (secondaryNeighbors.Data() != 0) {
    free(secondaryNeighbors.Detach());
  }

  // Pre-0xd save format stored the neighbor arrays directly; current saves rebuild them
  // (AppendUniquePrimaryNeighbor et al.) after load instead.
  if (g_nSaveFormatVersion < 0xd) {
    {
      short neighborCount;
      stream->ReadBytes(&neighborCount, 2);
      for (short neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        TZone* entry;
        stream->ReadBytes(&entry, 4);
        primaryNeighbors[static_cast<unsigned int>(neighborIndex)] = entry;
      }
    }

    {
      short neighborCount;
      stream->ReadBytes(&neighborCount, 2);
      for (short neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        Province* entry;
        stream->ReadBytes(&entry, 4);
        secondaryNeighbors[static_cast<unsigned int>(neighborIndex)] = entry;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0055eff0
void TZone::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteSharedString(&displayName);
  stream->WriteBytes(&statusCode04, 2);
  stream->WriteBytes(&tileOrTerrainId0c, 4);
  stream->WriteBytes(&seedNationId12, 2);
  stream->WriteBytes(&activeTileIndex20, 2);
  stream->WriteBytes(&contextOrdinal14, 2);
}

// FUNCTION: IMPERIALISM 0x0055f070
void TZone::AssignZoneDisplayNameToOutputRef(CString* outputRef) {
  *outputRef = displayName;
}

// FUNCTION: IMPERIALISM 0x0055f090
void TZone::AssignZoneDisplayNameAliasToOutputRef(CString* outputRef) {
  *outputRef = displayName;
}

// FUNCTION: IMPERIALISM 0x0055f0b0
short TZone::GetContextOrdinalOrInvalid() {
  if (this == 0) {
    return -1;
  }
  return contextOrdinal14;
}

// FUNCTION: IMPERIALISM 0x0055f100
TZone* FindMapActionContextByNodeId(short nodeId) {
  if (nodeId == -1) {
    return 0;
  }
  TZone* node;
  for (node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
    // Original inlines GetContextOrdinalOrInvalid (null -> -1, unreachable here).
    short ordinal = (node != 0) ? node->contextOrdinal14 : -1;
    if (ordinal == nodeId) {
      break;
    }
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x0055f140
int TZone::ComputeMapActionContextNodeValueAverage() {
  if (QueryPortZoneCapability()) {
    AssertValid();
    int ownerTag =
        g_pGlobalMapState->terrainStateTable[static_cast<TPortZone*>(this)->portTileIndex48]
            .ownerNationTag04;
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(ownerTag) != 0) {
      return g_pGlobalMapState
          ->cityScoreTable[g_apTerrainTypeDescriptorTable[ownerTag]->GetHomeRegionCityRecordIndex()]
          .cityScoreValue;
    }
  } else if (secondaryNeighbors.Count() != 0) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < static_cast<unsigned int>(secondaryNeighbors.Count()); ++i) {
      sum += g_pGlobalMapState
                 ->cityScoreTable[static_cast<short>(GetProvinceIndex(secondaryNeighbors[i]))]
                 .cityScoreValue;
    }
    return sum / secondaryNeighbors.Count();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055f300
void TZone::AppendUniquePrimaryNeighbor(TZone* zone) {
  primaryNeighbors.Add(zone);
}

// FUNCTION: IMPERIALISM 0x0055f440
char TZone::ContainsCityStatePointerInZoneArrayByCityIndex(short cityIndex) {
  unsigned int entryCount = static_cast<unsigned int>(this->secondaryNeighbors.Count());
  if (entryCount == 0) {
    return 0;
  }
  const Province* target = &g_pGlobalMapState->cityScoreTable[cityIndex];
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    // Inlined bounds-guarded stretch element access, as in the original (mirrors
    // HasSecondaryNeighborWithNationTag / IsZoneMaskOrArrayEntryPresentForKey).
    Province* const* entrySlot =
        (entryIndex < entryCount) ? this->secondaryNeighbors.Data() + entryIndex : 0;
    if (*entrySlot == target) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055f4d0
char TZone::HasSecondaryNeighborWithNationTag(short nationTag) {
  unsigned int entryCount = static_cast<unsigned int>(this->secondaryNeighbors.Count());
  if (entryCount == 0) {
    return 0;
  }
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    // Inlined bounds-guarded stretch element access, as in the original.
    Province* const* entrySlot =
        (entryIndex < entryCount) ? this->secondaryNeighbors.Data() + entryIndex : 0;
    short entryNationTag = (*entrySlot)->ownerNationCode00;
    if (entryNationTag == nationTag) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055f540
char TZone::IsZoneMaskOrArrayEntryPresentForKey(short key) {
  unsigned char keyBit = static_cast<unsigned char>(1 << key);
  if ((nationKeyMask10 & keyBit) != 0) {
    return 1;
  }
  unsigned int entryCount = static_cast<unsigned int>(this->secondaryNeighbors.Count());
  if (entryCount == 0) {
    return 0;
  }
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    // Inlined bounds-guarded stretch element access, as in the original.
    Province* const* entrySlot =
        (entryIndex < entryCount) ? this->secondaryNeighbors.Data() + entryIndex : 0;
    short entryKey = (*entrySlot)->ownerNationCode00;
    if (entryKey == key) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055f5c0
void TZone::GenerateZoneStatusCodeIfUnset() {
  if (statusCode04 != -1) {
    return; // status code already assigned
  }
  short category;
  if (QueryPortZoneCapability() != 0) {
    category = 5; // port zones are always the highest status band
  } else {
    category = static_cast<short>(primaryNeighbors.Count());
    if (category == 2) {
      // Is the second primary neighbor also a primary neighbor of the first? If so the
      // two share an edge and the context sits inside a cluster (category 1).
      TZone* neighbor0 = primaryNeighbors[0];
      unsigned int neighborCount = static_cast<unsigned int>(neighbor0->primaryNeighbors.Count());
      if (neighborCount != 0) {
        TZone** scan = neighbor0->primaryNeighbors.Data();
        TZone* target = primaryNeighbors[1];
        unsigned int i = 0;
        do {
          if (*scan == target) {
            category = 1;
            break;
          }
          i = i + 1;
          scan = scan + 1;
        } while (i < neighborCount);
      }
    }
    if (category > 5) {
      category = 4;
    } else if (category > 3) {
      category = 3;
    }
    if (secondaryNeighbors.Count() == 0) {
      category = 4;
    } else if (category == 4) {
      category = 3;
    }
  }
  g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
  statusCode04 =
      static_cast<short>(((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 3) + category * 4);
}

// FUNCTION: IMPERIALISM 0x0055f780
void TZone::GenerateMapActionContextDisplayNameAndHeadline(unsigned char* usedCityFlags,
                                                           const char* overrideName) {
  if (overrideName != 0) {
    CString providedName(overrideName);
    displayName = providedName;
  } else {
    int chosenCity = -1;
    // With a used-city bitmap and secondary neighbours, try to feature a random adjacent
    // city that has not been used yet.
    if (usedCityFlags != 0 && secondaryNeighbors.Count() != 0) {
      g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
      unsigned int pick = (g_zoneStatusCodePrngSeed_006a5aec >> 0xc & 0x7fff) %
                          static_cast<unsigned int>(secondaryNeighbors.Count());
      Province* cityRecord = secondaryNeighbors[pick];
      short tile = cityRecord->linkedTileIndices42[0];
      chosenCity = g_pGlobalMapState->terrainStateTable[tile].cityRecordIndex;
      if (usedCityFlags[chosenCity] != 0) {
        chosenCity = -1;
      } else {
        usedCityFlags[chosenCity] = 1;
      }
    }
    if (chosenCity != -1) {
      g_pGlobalMapState->AssignCityRecordDisplayName(chosenCity, &displayName);
    } else {
      if (g_pSimMgr->useLocalizedNameTables68 != 0) {
        // Walk the headline resource table with a random start + stride so successive
        // contexts get distinct names.
        if (g_mapActionContextDisplayNameCacheId_006984b8 == -1) {
          unsigned int randomValue = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35U + 1;
          int nameIndex = static_cast<int>((randomValue >> 0xc) & 0x7fff);
          g_mapActionContextDisplayNameCacheId_006984b8 = nameIndex % 0x25;
          unsigned int nextRandomValue = randomValue * 0x15a4e35U + 1;
          g_zoneStatusCodePrngSeed_006a5aec = nextRandomValue;
          int strides[4] = {1, 7, 0xb, 0x17};
          int strideSelector = static_cast<int>((nextRandomValue >> 0xc) & 0x7fff);
          int strideIndex = SignedRemainderByFour(strideSelector);
          g_mapActionContextDisplayNameCacheStep_006984bc = strides[strideIndex];
        }
        CString resourceName;
        g_pSimMgr->GetString(0x275b,
                             static_cast<short>(g_mapActionContextDisplayNameCacheId_006984b8),
                             &resourceName);
        displayName = resourceName;
        g_mapActionContextDisplayNameCacheId_006984b8 +=
            g_mapActionContextDisplayNameCacheStep_006984bc;
        if (g_mapActionContextDisplayNameCacheId_006984b8 >= 0x25) {
          g_mapActionContextDisplayNameCacheId_006984b8 -= 0x25;
        }
      } else {
        GenerateMappedFlavorTextByCurrentContextNation(&displayName);
      }
    }
  }
  // Build the headline by expanding the status-code-selected template with the display name.
  CString headlineTemplate;
  g_pSimMgr->GetString(0x275a, statusCode04, &headlineTemplate);
  CString expanded;
  scanBracketExpressions(g_pSimMgr, &expanded, headlineTemplate, static_cast<LPCSTR>(displayName));
  displayName = expanded;
}

// TEMPLATE: IMPERIALISM 0x0055fae0
// stretch::OverStretch

// FUNCTION: IMPERIALISM 0x0055fb60
void TZone::SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex) {
  seedNationId12 = static_cast<short>(nationSeedId);
  unsigned short resolvedTile = static_cast<unsigned short>(tileIndex);
  if (resolvedTile == 0xffff) {
    resolvedTile = static_cast<unsigned short>(
        g_pGlobalMapState->ComputeRepresentativeTileIndexForNationWithWrapBias(
            static_cast<short>(nationSeedId), 0));
  }
  tileOrTerrainId0c = static_cast<short>(resolvedTile);
  activeTileIndex20 = static_cast<short>(tileOrTerrainId0c);
  if (QueryPortZoneCapability() != 0) {
    SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                         -kMapTileActionStatePortZoneMarkerFrame);
    return;
  }
  SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                       -kMapTileActionStateZoneCenterMarkerFrame);
  activeTileIndex20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
      activeTileIndex20, kStrategicHexDirectionNorthWest);
  SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                       -kMapTileActionStateZoneNorthWestMarkerFrame);
  activeTileIndex20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
      activeTileIndex20, kStrategicHexDirectionNorthEast);
  SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                       -kMapTileActionStateZoneNorthEastMarkerFrame);
}

// 0x00564570 (FindMapActionContextContainingNodeByIndex) is a real TOcean __thiscall
// method; body lives in TOcean.cpp.

// FUNCTION: IMPERIALISM 0x0055fc40
void TZone::HandleKeyDown(int key_id) {
  short sVarSlotId;
  short sVarActiveSlot;
  TShip* pvNode;
  int nSlotsRemaining;
  bool bSlotIsActive;
  unsigned int uSlotIndex;
  unsigned int uSlotCountLocal;
  Province** piSlotEntry;
  Province** slotTable = secondaryNeighbors.Data();
  unsigned int slotCount = static_cast<unsigned int>(secondaryNeighbors.GetSize());

  if ((nationKeyMask10 & (1U << ((unsigned char)key_id & 0x1f))) == 0) {
    nationKeyMask10 =
        static_cast<unsigned short>(nationKeyMask10 | (1U << ((unsigned char)key_id & 0x1f)));
    sVarSlotId = g_pSimMgr->GetActiveNationId();

    if ((nationKeyMask10 & (1U << ((unsigned char)sVarSlotId & 0x1f))) == 0) {
      uSlotCountLocal = slotCount;
      uSlotIndex = 0;
      if (uSlotCountLocal != 0) {
        do {
          if (uSlotIndex < uSlotCountLocal) {
            piSlotEntry = slotTable + static_cast<int>(uSlotIndex);
          } else {
            piSlotEntry = 0;
          }
          if ((*piSlotEntry)->ownerNationCode00 == static_cast<char>(sVarSlotId)) {
            goto LAB_0055fcae;
          }
          uSlotIndex = uSlotIndex + 1;
        } while (uSlotIndex < uSlotCountLocal);
      }
      bSlotIsActive = false;
    } else {
    LAB_0055fcae:
      bSlotIsActive = true;
    }

    if (bSlotIsActive) {
      if (sVarSlotId == static_cast<short>(key_id)) {
        SetMapOrderUiFlag(1);
        key_id = sVarSlotId + 1;
        nSlotsRemaining = 6;
        do {
          if ((nationKeyMask10 & (1U << ((unsigned char)(key_id % 7) & 0x1f))) != 0) {
            sVarSlotId = GetActiveNationSlotTile();
            SetMapTileStateByteAndNotifyObserver(sVarSlotId,
                                                 key_id % 7 + kMapTileActionStateNationOrderFirst);
            g_pGlobalMapState->terrainStateTable[sVarSlotId].tileActionOrdinal1a = -1;
          }
          key_id = key_id + 1;
          nSlotsRemaining = nSlotsRemaining - 1;
        } while (nSlotsRemaining != 0);
      } else {
        sVarSlotId = GetActiveNationSlotTile();
        SetMapTileStateByteAndNotifyObserver(sVarSlotId, kMapTileActionStateNationOrderFirst);
        g_pGlobalMapState->terrainStateTable[sVarSlotId].tileActionOrdinal1a = -1;
      }
    }
  }

  sVarActiveSlot = g_pSimMgr->GetActiveNationId();
  if (sVarActiveSlot == -1) {
    sVarActiveSlot = g_pSimMgr->GetActiveNationId();
  }

  if ((nationKeyMask10 & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
    for (pvNode = TShip::GetFirst(); pvNode != 0; pvNode = pvNode->next) {
      if (((pvNode->location == this) && (pvNode->nation == sVarActiveSlot)) &&
          (pvNode->taskForce == 0)) {
        SetMapOrderUiFlag(1);
        return;
      }
    }
  }
  SetMapOrderUiFlag(0);
}

// FUNCTION: IMPERIALISM 0x0055fe60
short TZone::FindNearestActiveSeaContextTileFromOffset216() {
  short stepSign = 1;
  short tileIndex = static_cast<short>(tileOrTerrainId0c + 0xd8);
  short stepMagnitude = 1;
  for (;;) {
    TTerrainStateRecordView& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tileRecord.tileActionState16 == kMapTileActionStateNone) {
      short nationId = static_cast<short>(tileRecord.ownerNationTag04);
      TZone* contextZone = 0;
      if (nationId >= 0x17 && g_pActiveMapOrderContext != 0) {
        contextZone = &g_pActiveMapOrderContext->contextArray[nationId - 0x17];
      }
      if (contextZone != 0) {
        return tileIndex;
      }
    }
    tileIndex = static_cast<short>(tileIndex + stepSign * stepMagnitude);
    stepMagnitude = static_cast<short>(stepMagnitude + 1);
    stepSign = static_cast<short>(-stepSign);
  }
}

// FUNCTION: IMPERIALISM 0x0055fef0
short TZone::GetActiveNationSlotTile() {
  short tileIndex = static_cast<short>(tileOrTerrainId0c);
  short stepSign = 1;
  short stepMagnitude = 1;
  for (;;) {
    TTerrainStateRecordView& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tileRecord.tileActionState16 == kMapTileActionStateNone) {
      short nationId = static_cast<short>(tileRecord.ownerNationTag04);
      TZone* contextZone = 0;
      if (nationId >= 0x17 && g_pActiveMapOrderContext != 0) {
        contextZone = &g_pActiveMapOrderContext->contextArray[nationId - 0x17];
      }
      if (contextZone != 0) {
        return tileIndex;
      }
    }
    tileIndex = static_cast<short>(tileIndex + stepMagnitude * stepSign);
    stepMagnitude = static_cast<short>(stepMagnitude + 1);
    stepSign = static_cast<short>(-stepSign);
  }
}

// FUNCTION: IMPERIALISM 0x0055ff70
int TZone::ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, TZone* contextZone,
                                                          Province* contextProvince) {
  TTerrainStateRecordView& tileRecord =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)];
  if (tileRecord.GetTerrainKind() != kStrategicTerrainWater) {
    return 0;
  }
  if (tileRecord.tileActionState16 != kMapTileActionStateNone) {
    return 0;
  }
  TZone* zoneForTile = 0;
  if (g_pActiveMapOrderContext != 0) {
    zoneForTile = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(static_cast<short>(tileIndex));
  }
  if (zoneForTile != contextZone) {
    return 0x3e8;
  }

  int score = 0x1388;
  int neighborDir = 0;
  do {
    short neighborTile = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
        static_cast<short>(tileIndex), static_cast<short>(neighborDir));
    if (neighborTile != -1) {
      TTerrainStateRecordView& neighborRecord = g_pGlobalMapState->terrainStateTable[neighborTile];
      if (neighborRecord.GetTerrainKind() == kStrategicTerrainWater) {
        signed char neighborSubtype = static_cast<signed char>(neighborRecord.tileActionState16);
        if (neighborSubtype == kMapTileActionStateAnchor ||
            neighborSubtype == kMapTileActionStateDockedFleet) {
          TZone* portZone = TZone::FindPortZoneByTile(neighborTile);
          if (portZone != contextZone) {
            score = score - 1;
          }
        } else {
          short cityStateLink = neighborRecord.cityRecordIndex;
          Province* province = 0;
          if (cityStateLink != -1) {
            province = &g_pGlobalMapState->cityScoreTable[cityStateLink];
          }
          if (province == contextProvince) {
            score = score + 0x64;
          } else {
            score = score - 0xa;
          }
        }
      }
    }
    neighborDir = neighborDir + 1;
  } while (neighborDir < 6);

  return score;
}

// FUNCTION: IMPERIALISM 0x00560150
short TZone::FindBestCoastalTileForContextAndCityStateByHeuristic(Province* contextProvince) {
  short tileCandidate = 0;

  for (;;) {
    TTerrainStateRecordView& tileRecord = g_pGlobalMapState->terrainStateTable[tileCandidate];
    int isWater = tileRecord.GetTerrainKind() == kStrategicTerrainWater;
    if (isWater) {
      TZone* zoneForTile;
      short tileActionState = static_cast<signed char>(tileRecord.tileActionState16);
      if (tileActionState == kMapTileActionStateAnchor ||
          tileActionState == kMapTileActionStateDockedFleet) {
        zoneForTile = TZone::FindPortZoneByTile(tileCandidate);
      } else {
        short nationCode = tileRecord.ownerNationTag04;
        if (nationCode < kFirstMapRegionNationTag) {
          zoneForTile = 0;
        } else {
          zoneForTile =
              &g_pActiveMapOrderContext->contextArray[nationCode - kFirstMapRegionNationTag];
        }
      }
      if (zoneForTile == this) {
        int neighborDir = 0;
        do {
          short neighborTile = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
              tileCandidate, static_cast<short>(neighborDir));
          if (neighborTile != -1) {
            TTerrainStateRecordView& neighborRecord =
                g_pGlobalMapState->terrainStateTable[neighborTile];
            int neighborIsWater = neighborRecord.GetTerrainKind() == kStrategicTerrainWater;
            if (!neighborIsWater) {
              short cityStateLink = neighborRecord.cityRecordIndex;
              Province* province = 0;
              if (cityStateLink != -1) {
                province = &g_pGlobalMapState->cityScoreTable[cityStateLink];
              }
              if (province == contextProvince) {
                break;
              }
            }
          }
          neighborDir = neighborDir + 1;
        } while (neighborDir < 6);
        if (neighborDir < 6) {
          break;
        }
      }
    }
    tileCandidate = static_cast<short>(tileCandidate + 1);
    if (tileCandidate >= 0x1950) {
      break;
    }
  }

  if (tileCandidate >= 0x1950) {
    tileCandidate = static_cast<short>(tileOrTerrainId0c + 0x6c);
  }

  short bestTile = tileCandidate;
  int bestTileIndex = static_cast<int>(bestTile);
  int bestScore =
      ScoreCoastalTileForContextAndCityStateAffinity(bestTileIndex, this, contextProvince);

  HexSpiralSearchState spiral;
  spiral.row = bestTileIndex / 0x6c;
  spiral.col = bestTileIndex % 0x6c;
  spiral.ring = 0;
  spiral.direction = 5;
  spiral.stepInRing = 1;
  TMapMgr::AdvanceSpiralSearchStateAndStepHexCoordinates(&spiral);

  while (spiral.ring < 0xc) {
    short spiralTile = InlineTileIndexFromRowCol(spiral.row, spiral.col);

    bool tileInBounds;
    if ((spiralTile < 0) || (0x194f < spiralTile)) {
      tileInBounds = false;
    } else {
      tileInBounds = true;
    }

    if (tileInBounds) {
      int spiralTileIndex = InlineTileIndexFromRowCol(spiral.row, spiral.col);
      int candidateScore =
          ScoreCoastalTileForContextAndCityStateAffinity(spiralTileIndex, this, contextProvince);
      if (bestScore < candidateScore) {
        bestScore = candidateScore;
        tileCandidate = InlineTileIndexFromRowCol(spiral.row, spiral.col);
      }
    }

    bestTile = tileCandidate;
    spiral.stepInRing = spiral.stepInRing + 1;
    if (spiral.ring <= spiral.stepInRing) {
      spiral.stepInRing = 0;
      spiral.direction = spiral.direction + 1;
      if (5 < spiral.direction) {
        spiral.ring = spiral.ring + 1;
        spiral.direction = 0;
        TMapMgr::StepHexRowColByDirectionWithWrapRules(&spiral.row, &spiral.col,
                                                       kStrategicHexDirectionWest);
      }
    }
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&spiral.row, &spiral.col, spiral.direction);
  }

  return bestTile;
}

// FUNCTION: IMPERIALISM 0x00560580
void TZone::SetMapOrderUiFlag(bool flag) {
  unsigned char tileStateByte =
      g_pGlobalMapState->terrainStateTable[activeTileIndex20].tileActionState16;
  if (((static_cast<unsigned char>(flag) !=
        static_cast<unsigned char>(static_cast<signed char>(tileStateByte) < 0 ? 1 : 0)) &&
       (g_pUiRuntimeContext != 0)) &&
      (g_pUiRuntimeContext->mapUberPictureF0 != 0)) {
    char sign = static_cast<char>((-(static_cast<int>(flag)) & 2) - 1);
    if (QueryPortZoneCapability() != 0) {
      SetMapTileStateByteAndNotifyObserver(
          activeTileIndex20, static_cast<int>(sign) * kMapTileActionStatePortZoneMarkerFrame);
      NotifyMapUberPictureTileMarker(activeTileIndex20);
      return;
    }
    int magnitude = static_cast<int>(sign);
    SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                         magnitude * kMapTileActionStateZoneCenterMarkerFrame);
    NotifyMapUberPictureTileMarker(activeTileIndex20);
    activeTileIndex20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
        activeTileIndex20, kStrategicHexDirectionNorthWest);
    SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                         magnitude * kMapTileActionStateZoneNorthWestMarkerFrame);
    NotifyMapUberPictureTileMarker(activeTileIndex20);
    activeTileIndex20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
        activeTileIndex20, kStrategicHexDirectionNorthEast);
    SetMapTileStateByteAndNotifyObserver(activeTileIndex20,
                                         magnitude * kMapTileActionStateZoneNorthEastMarkerFrame);
    NotifyMapUberPictureTileMarker(activeTileIndex20);
  }
}

// Builds the human-readable source line for a naval-intelligence report. Mac's
// resource strings identify the two cases as an admiral/ship attribution and an
// anonymous phone call.
// FUNCTION: IMPERIALISM 0x005606f0
void TZone::BuildNavalIntelligenceSourceDescription(CString* out, short nation) {
  TShip* selected = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this && ship->nation == nation) {
      selected = ship->Finest(selected, 0);
    }
  }

  if (selected == 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(out, 0x2762, 0x10);
    return;
  }

  if (selected->admiral != 0) {
    CString admiralName;
    CString shipName;
    CString reportTemplate;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0xe);
    admiralName = s_szAdmiralPrefix_0069578c + selected->admiral->displayName;
    shipName = selected->name;
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(admiralName), static_cast<LPCSTR>(shipName));
  } else {
    CString shipName;
    CString reportTemplate;
    shipName = selected->name;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0xf);
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(shipName));
  }
}

// FUNCTION: IMPERIALISM 0x00560970
TAdmiral* TZone::FindReportingAdmiralForNation(short nation) {
  TShip* selected = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this && ship->nation == nation) {
      selected = ship->Finest(selected, 0);
    }
  }
  return selected != 0 ? selected->admiral : 0;
}

// FUNCTION: IMPERIALISM 0x005609e0
TTaskForce* TZone::CreateTaskForceFromNavyOrdersForNationIfEligible(short nation) {
  int resolvedNation = nation;
  if (resolvedNation == -1) {
    resolvedNation = g_pSimMgr->GetActiveNationId();
  }
  unsigned char nationBit = static_cast<unsigned char>(1 << static_cast<short>(resolvedNation));
  if ((nationKeyMask10 & nationBit) != 0) {
    for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
      if (ship->location == this && ship->nation == resolvedNation && ship->taskForce == 0) {
        // requiredCount seeds from the raw incoming nation arg, which the original keeps
        // distinct from the active-nation-resolved slot used above.
        TTaskForce* taskForce = new TTaskForce(this, nation);
        taskForce->ITaskForce();
        taskForce->MaxOut(0);
        taskForce->DemocraticallyDetermineAggressionLevel();
        return taskForce;
      }
    }
  }
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00560b00
char TZone::CanDisplayMapOrderEntryInCurrentContext(short nation, char skipField34Check) {
  if (nation == -1) {
    nation = g_pSimMgr->GetActiveNationId();
  }
  unsigned char nationBit = static_cast<unsigned char>(1 << nation);
  if ((nationKeyMask10 & nationBit) == 0) {
    return 0;
  }
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this && ship->nation == nation) {
      if (skipField34Check == 0) {
        unsigned char hasField34 = (ship->selection != 0);
        if (hasField34 != 0) {
          continue;
        }
      }
      if (ship->taskForce == 0) {
        return 1;
      }
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00560ba0
void TZone::ExpandTaskForceTraversalDepthAndMarkDeferredNodes(int remainingDepth,
                                                              char markAdjacentCities) {
  short depth = static_cast<short>(remainingDepth);
  if (distanceLevel44 > depth) {
    return;
  }

  distanceLevel44 = static_cast<short>(depth + 1);
  // Ground truth tests the depth once and skips both passes together (the single
  // `jle` after `mov word ptr [esi+0x44], cx` at 0x560bbd), so the city-marking
  // pass nests inside the depth check rather than re-testing it.
  if (depth > 0) {
    for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
      TZone* neighbor = primaryNeighbors.GetAt(i);
      if (markAdjacentCities != 0 || neighbor->QueryZoneCapabilityFlagA()) {
        neighbor->ExpandTaskForceTraversalDepthAndMarkDeferredNodes(depth - 1, 0);
      }
    }

    if (markAdjacentCities != 0) {
      for (int i = secondaryNeighbors.Count() - 1; i >= 0; --i) {
        Province* city = secondaryNeighbors.Data()[i];
        city->navyOrderReachableA0 = 1;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00560e20
void ResetMapActionContextActivityAndNationFlags() {
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    zone->distanceLevel44 = 0;
  }
  for (int cityIndex = 0; cityIndex < 0x180; ++cityIndex) {
    g_pGlobalMapState->cityScoreTable[cityIndex].navyOrderReachableA0 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00560e70
TZone* TZone::SelectBestPrimaryNeighborForNationDiplomacyMask(int nationSlot) {
  TZone* bestNeighbor = 0;
  int bestWarCount = -1;
  for (int neighborIndex = 0; neighborIndex < primaryNeighbors.GetSize(); ++neighborIndex) {
    TZone* neighbor = primaryNeighbors.GetAt(neighborIndex);
    if (!neighbor->QueryPortZoneCapability() || neighbor->QueryZoneCapabilityFlagD(nationSlot)) {
      int warCount = 0;
      for (int otherNation = 0; otherNation < 7; ++otherNation) {
        if (g_apTerrainTypeDescriptorTable[otherNation] != 0 &&
            (neighbor->nationKeyMask10 & (1 << otherNation)) != 0 &&
            g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, otherNation)) {
          ++warCount;
        }
      }
      if (bestWarCount < warCount) {
        bestWarCount = warCount;
        bestNeighbor = neighbor;
      }
    }
  }
  return bestNeighbor;
}

// FUNCTION: IMPERIALISM 0x00560f80
void TZone::PropagateMapActionContextDistanceLevelsRecursive(short level) {
  if (level == -1) {
    for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
      node->distanceLevel44 = 0x29a;
    }
    level = 0;
  }
  if (level < distanceLevel44) {
    distanceLevel44 = level;
    for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
      TZone* neighbor = primaryNeighbors[static_cast<unsigned int>(i)];
      neighbor->PropagateMapActionContextDistanceLevelsRecursive(static_cast<short>(level + 1));
    }
  }
}

// FUNCTION: IMPERIALISM 0x005610b0
short TZone::GetCachedMapActionContextDistanceOrRecompute(TZone* other) {
  if (other == this) {
    return 0;
  }

  if (g_pMapActionContextDistanceCache == 0 ||
      g_nMapActionContextCount != g_nMapActionContextDistanceCacheSizedFor) {
    g_nMapActionContextDistanceCacheSizedFor = g_nMapActionContextCount;
    int cellCount = g_nMapActionContextCount * g_nMapActionContextCount;
    char* newCache = new char[cellCount];
    for (int i = 0; i < cellCount; ++i) {
      newCache[i] = static_cast<char>(0xff);
    }
    g_pMapActionContextDistanceCache = newCache;
  }

  short thisOrd = this != 0 ? contextOrdinal14 : -1;
  short otherOrd = other != 0 ? other->contextOrdinal14 : -1;
  char* cache = static_cast<char*>(g_pMapActionContextDistanceCache);
  signed char cachedDistance = cache[thisOrd * g_nMapActionContextCount + otherOrd];

  if (cachedDistance < 0) {
    for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
      node->distanceLevel44 = 0x29a;
    }

    if (distanceLevel44 > 0) {
      distanceLevel44 = 0;
      for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
        TZone* neighbor = primaryNeighbors[static_cast<unsigned int>(i)];
        neighbor->PropagateMapActionContextDistanceLevelsRecursive(1);
      }
    }

    for (TZone* writeNode = g_pMapActionContextListHead; writeNode != 0;
         writeNode = writeNode->prev18) {
      short nodeOrd = writeNode != 0 ? writeNode->contextOrdinal14 : -1;
      cache = static_cast<char*>(g_pMapActionContextDistanceCache);
      cache[thisOrd * g_nMapActionContextCount + nodeOrd] =
          static_cast<char>(writeNode->distanceLevel44);
      cache[nodeOrd * g_nMapActionContextCount + thisOrd] =
          static_cast<char>(writeNode->distanceLevel44);
    }

    cache = static_cast<char*>(g_pMapActionContextDistanceCache);
    cachedDistance = cache[thisOrd * g_nMapActionContextCount + otherOrd];
  }

  return static_cast<unsigned char>(cachedDistance);
}

// TEMPLATE: IMPERIALISM 0x00561300
// stretch::OverStretch

// FUNCTION: IMPERIALISM 0x00561400
unsigned int TZone::BuildNationBitmaskForActiveType3Or4OrdersIncludingNation(unsigned char nation) {
  unsigned int mask = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this) {
      TTaskForce* entry = ship->taskForce;
      if (entry != 0 && entry->defeated == 0 &&
          (entry->shipOrders == 3 || entry->shipOrders == 4)) {
        mask |= 1u << (ship->nation & 0x1f);
      }
    }
  }
  return (1u << (nation & 0x1f)) | mask;
}

// FUNCTION: IMPERIALISM 0x00561490
unsigned int TZone::BuildNationBitmaskForActiveType3Or4Orders() {
  unsigned int mask = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this) {
      TTaskForce* entry = ship->taskForce;
      if (entry != 0 && entry->defeated == 0 &&
          (entry->shipOrders == 3 || entry->shipOrders == 4)) {
        mask |= 1u << (ship->nation & 0x1f);
      }
    }
  }
  return mask;
}

// FUNCTION: IMPERIALISM 0x00561510
unsigned int TZone::HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask(int nation) {
  unsigned int mask = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this) {
      TTaskForce* entry = ship->taskForce;
      if (entry != 0 && entry->defeated == 0 &&
          (entry->shipOrders == 3 || entry->shipOrders == 4)) {
        mask |= 1u << (ship->nation & 0x1f);
      }
    }
  }
  if ((mask & (1u << (static_cast<unsigned char>(nation) & 0x1f))) != 0) {
    return 0;
  }
  int candidate = 0;
  while ((mask & (1u << (candidate & 0x1f))) == 0 ||
         g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(candidate, nation) ==
             0) {
    ++candidate;
    if (candidate > 6) {
      return 0;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005619e0
void TZone::ResolvePortZoneOwnerContextAndDispatch() {
  short tileIndex = FindNearestActiveSeaContextTileFromOffset216();
  short ownerNation = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  TZone* contextElement = &g_pActiveMapOrderContext->contextArray[ownerNation - 0x17];
  primaryNeighbors.Add(contextElement);
  contextElement->primaryNeighbors.Add(this);
}

// FUNCTION: IMPERIALISM 0x00561b90
short TZone::GetPortZoneOwnerNationCodeFromMissionField48() {
  short tileIndex = static_cast<TPortZone*>(this)->portTileIndex48;
  return g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
}

// FUNCTION: IMPERIALISM 0x00561bf0
TZone* TZone::FindPortZoneByTile(short nTileIndex) {
  TZone* zone = g_pMapActionContextListHead;
  while (zone != 0 && zone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    zone = zone->prev18;
  }
  for (;;) {
    if (zone == 0) {
      return 0;
    }
    if (static_cast<short>(zone->tileOrTerrainId0c) == nTileIndex ||
        zone->activeTileIndex20 == nTileIndex ||
        static_cast<TPortZone*>(zone)->portTileIndex48 == nTileIndex) {
      return zone;
    }
    zone = zone->prev18;
    while (zone != 0 && zone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      zone = zone->prev18;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00561c80
TZone* TZone::GetFirstPortZone() {
  TZone* cursor = g_pMapActionContextListHead;
  while (cursor != 0 && cursor->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    cursor = cursor->prev18;
  }
  return cursor;
}

// FUNCTION: IMPERIALISM 0x00561d40
TZone* TZone::GetNextPortZone() {
  TZone* cursor = this->prev18;
  while (cursor != 0 && cursor->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    cursor = cursor->prev18;
  }
  return cursor;
}

// Unlinks this zone from g_pMapActionContextListHead (via prev18/next1c); member
// teardown (secondaryNeighbors, primaryNeighbors, displayName) happens automatically in
// reverse declaration order. Ground truth for this function is reached via the vector
// deleting destructor's thunk at 0x407775; TPortZone::~TPortZone (0x5616f0) is
// instruction-for-instruction identical since TPortZone has no unique members of its own
// -- the original inlined this same body there too instead of calling it out-of-line.
// Exact-capacity fallback emitted for the primary-neighbor pointer stretch.
// TEMPLATE: IMPERIALISM 0x005620c0
// ?SetCapacity@?$stretch@PAVTZone@@@@QAEXI@Z
template void stretch<TZone*>::SetCapacity(unsigned int);

// FUNCTION: IMPERIALISM 0x005627a0
TZone::~TZone() {
  if (g_pMapActionContextListHead == this) {
    g_pMapActionContextListHead = prev18;
  }
  if (prev18 != 0) {
    prev18->next1c = next1c;
  }
  if (next1c != 0) {
    next1c->prev18 = prev18;
  }
  next1c = 0;
  prev18 = 0;
}

// PortZone vtable bodies (0x005616c0..0x00561e40) live in TPortZone.cpp.

// SYNTHETIC: IMPERIALISM 0x00562880
// TZone::`vector deleting destructor'

// Reseeds the zone status-code PRNG from a hash of the scenario tag string (falling back
// to the wall clock when the tag hashes to zero), then walks the whole map-action-context
// list assigning each zone a status code and refreshing its display name/headline.
// FUNCTION: IMPERIALISM 0x00563220
void RegenerateAllMapActionContextStatusCodes(void) {
  const char* tag = g_pGlobalMapState->scenarioTagText1c;
  int seed = kControlTagNada;
  while (*tag != '\0') {
    seed = (seed >> 0x10) + seed * 2 + static_cast<int>(*tag);
    tag = tag + 1;
  }
  g_zoneStatusCodePrngSeed_006a5aec = seed;
  if (seed == 0) {
    g_zoneStatusCodePrngSeed_006a5aec = time(0);
  }
  g_mapActionContextDisplayNameCacheId_006984b8 = -1;

  unsigned char statusScratch[0x180];
  memset(statusScratch, 0, sizeof(statusScratch));

  for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
    node->GenerateZoneStatusCodeIfUnset();
    node->GenerateMapActionContextDisplayNameAndHeadline(statusScratch, 0);
  }

  g_zoneStatusCodePrngSeed_006a5aec = 0;
  g_zoneStatusCodePrngSeed_006a5aec = time(0);
}

// Walks every map tile; for each coastal/port tile (anchor or docked-fleet marker) or land tile
// in a city region, resolves the owning map-action context (a port zone matched by tile id,
// or the region-indexed context) and, for each of the tile's 6 hex neighbours that carries a
// city record, adds that city context to the owning context's secondary-neighbour list.
// FUNCTION: IMPERIALISM 0x00563da0
void PopulatePortZoneAdjacencyToNearbyCityContexts(void) {
  int tileIndex = 0;
  do {
    TZone* context;
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    short marker = tile.tileActionState16;
    if (marker == kMapTileActionStateAnchor || marker == kMapTileActionStateDockedFleet) {
      // Inlined FindPortZoneByTile(tileIndex): match a port zone by any of its tile ids.
      context = TZone::GetFirstPortZone();
      while (context != 0) {
        short ti = static_cast<short>(tileIndex);
        if (static_cast<short>(context->tileOrTerrainId0c) == ti ||
            context->activeTileIndex20 == ti ||
            static_cast<TPortZone*>(context)->portTileIndex48 == ti) {
          break;
        }
        context = context->GetNextPortZone();
      }
    } else {
      short region = tile.ownerNationTag04;
      if (region >= 0x17) {
        context = &g_pActiveMapOrderContext->contextArray[region - 0x17];
      } else {
        context = 0;
      }
    }

    if (context != 0) {
      int direction = 0;
      do {
        short neighborTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(
            static_cast<short>(tileIndex), static_cast<short>(direction));
        if (neighborTile != -1) {
          short cityIdx = g_pGlobalMapState->terrainStateTable[neighborTile].cityRecordIndex;
          Province* cityRecord;
          if (cityIdx == -1) {
            cityRecord = 0;
          } else {
            cityRecord = &g_pGlobalMapState->cityScoreTable[cityIdx];
          }
          if (cityRecord != 0) {
            // Append the neighbour's city context to the secondary list if not already present.
            Province** match = 0;
            if (context->secondaryNeighbors.Count() != 0) {
              Province** entries = context->secondaryNeighbors.Data();
              unsigned int j = 0;
              Province** scan = entries;
              do {
                if (*scan == cityRecord) {
                  match = entries + j;
                  break;
                }
                j = j + 1;
                scan = scan + 1;
              } while (j < static_cast<unsigned int>(context->secondaryNeighbors.Count()));
            }
            if (match == 0) {
              context->secondaryNeighbors.Add(cityRecord);
            }
          }
        }
        direction = direction + 1;
      } while (direction < 6);
    }

    tileIndex = tileIndex + 1;
  } while (static_cast<short>(tileIndex) < 0x1950);
}

// Walks every map tile, resolving each to its owning map-order context the same way
// PopulatePortZoneAdjacencyToNearbyCityContexts does (port zone matched by tile id, or the
// region-indexed nation context). If the context is itself a capable port zone with no
// primaryNeighbors yet, links it bidirectionally with its owning nation's context (mirrors
// ResolvePortZoneOwnerContextAndDispatch, reading tileOrTerrainId0c directly instead of
// searching outward via FindNearestActiveSeaContextTileFromOffset216). Otherwise, for each
// of the tile's 6 hex neighbours: a neighbour with a city record resolves to that city's
// Province and is appended (if absent) to secondaryNeighbors; a neighbour
// without one resolves to a port zone or region context (same two-way match as above) and,
// unless it's this same context or itself a capable port zone, is appended (if absent) to
// primaryNeighbors. This backfills the primary/secondary neighbour graph for contexts the
// map-gen pass (PopulatePortZoneAdjacencyToNearbyCityContexts) didn't already reach.
// FUNCTION: IMPERIALISM 0x00563f50
void RefreshPortZoneNeighborContextLinksAndFallbacks(void) {
  for (int tileIndex = 0; static_cast<short>(tileIndex) < 0x1950; ++tileIndex) {
    TTerrainStateRecordView& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    TZone* zone;
    if (tileRecord.tileActionState16 == kMapTileActionStateAnchor ||
        tileRecord.tileActionState16 == kMapTileActionStateDockedFleet) {
      zone = TZone::FindPortZoneByTile(static_cast<short>(tileIndex));
    } else if (tileRecord.ownerNationTag04 >= 0x17) {
      zone = &g_pActiveMapOrderContext->contextArray[tileRecord.ownerNationTag04 - 0x17];
    } else {
      zone = 0;
    }

    if (zone != 0 && zone->QueryPortZoneCapability()) {
      if (zone->primaryNeighbors.Count() == 0) {
        short tileIdx = static_cast<short>(zone->tileOrTerrainId0c);
        short ownerNation = g_pGlobalMapState->terrainStateTable[tileIdx].ownerNationTag04;
        TZone* contextElement = &g_pActiveMapOrderContext->contextArray[ownerNation - 0x17];
        zone->primaryNeighbors.Add(contextElement);
        contextElement->primaryNeighbors.Add(zone);
      }
    } else if (zone != 0) {
      for (int direction = 0; direction < 6; ++direction) {
        short neighborTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(
            static_cast<short>(tileIndex), static_cast<short>(direction));
        if (neighborTile == -1) {
          continue;
        }

        TTerrainStateRecordView& neighborRecord =
            g_pGlobalMapState->terrainStateTable[neighborTile];
        if (neighborRecord.cityRecordIndex != -1) {
          Province* candidate = &g_pGlobalMapState->cityScoreTable[neighborRecord.cityRecordIndex];
          if (!zone->secondaryNeighbors.ContainsEntry(candidate)) {
            zone->secondaryNeighbors.Add(candidate);
          }
          continue;
        }

        TZone* candidateContext;
        if (neighborRecord.tileActionState16 == kMapTileActionStateAnchor ||
            neighborRecord.tileActionState16 == kMapTileActionStateDockedFleet) {
          // Inlined FindPortZoneByTile(neighborTile): match a port zone by any of its tile ids.
          candidateContext = TZone::GetFirstPortZone();
          while (candidateContext != 0) {
            if (static_cast<short>(candidateContext->tileOrTerrainId0c) == neighborTile ||
                candidateContext->activeTileIndex20 == neighborTile ||
                static_cast<TPortZone*>(candidateContext)->portTileIndex48 == neighborTile) {
              break;
            }
            candidateContext = candidateContext->GetNextPortZone();
          }
        } else if (neighborRecord.ownerNationTag04 >= 0x17) {
          candidateContext =
              &g_pActiveMapOrderContext->contextArray[neighborRecord.ownerNationTag04 - 0x17];
        } else {
          candidateContext = 0;
        }

        if (candidateContext != 0 && candidateContext != zone &&
            !candidateContext->QueryPortZoneCapability() &&
            !zone->primaryNeighbors.ContainsEntry(candidateContext)) {
          zone->primaryNeighbors.Add(candidateContext);
        }
      }
    }
  }
}
