#include "game/TZone.h"
#include "game/global_data_tables.h"

#include <new>

#include "game/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/TGlobalMapState.h"
#include "game/TOcean.h"
#include "game/TPortZone.h"
#include "game/TSimMgr.h"
#include "game/UiRuntimeContext.h"

extern "C" char g_pClassDescTZone = 0;

undefined4 ReallocateHeapBlockWithAllocatorTracking(void);
undefined4 GetCurrentLocalEpochSecondsWithTimezoneCache(void);
// Localization template expander: substitutes bracket expressions in `input` using the
// variadic values, writing the result into `out` (a CString). __cdecl variadic.
void scanBracketExpressions(void* ctx, void* out, const char* input, ...);

namespace {

void DeleteUnlinkedZone(TZone* zone) {
  delete zone;
}

void* ReallocateStretchEntries(TZone** entries, int sizeBytes) {
  return reinterpret_cast<void*(__cdecl*)(void*, int)>(ReallocateHeapBlockWithAllocatorTracking)(
      entries, sizeBytes);
}

template <typename TStretch> void AppendZonePointerToStretch(TStretch* list, TZone* entry) {
  int slotIndex = list->Count();
  if (list->Capacity() <= slotIndex) {
    int nextCapacity = slotIndex + 1;
    unsigned int doubledCapacity = static_cast<unsigned int>(nextCapacity * 2);
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grownBuffer = ReallocateStretchEntries(list->Data(), nextCapacity * 8);
    if (grownBuffer == 0) {
      list->Data() = static_cast<TZone**>(ReallocateStretchEntries(list->Data(), nextCapacity * 4));
      list->Capacity() = nextCapacity;
    } else {
      list->Data() = static_cast<TZone**>(grownBuffer);
      list->Capacity() = static_cast<int>(doubledCapacity);
    }
  }
  if (list->Count() <= slotIndex) {
    list->Count() = slotIndex + 1;
  }
  list->Data()[slotIndex] = entry;
}

} // namespace

void TZone::InvokeObjectVtableMethod24() {
  HandleTurnEventVtableSlot24CopyPayloadBuffer();
}

void* TZone::HandleTurnEventVtableSlot24CopyPayloadBuffer() {
  CRuntimeClass* runtimeClass = GetRuntimeClass();
  unsigned int payloadSize = static_cast<unsigned int>(runtimeClass->m_nObjectSize);
  runtimeClass = GetRuntimeClass();
  CObject* destObject = runtimeClass->CreateObject();
  if (destObject == 0) {
    return 0;
  }
  unsigned int* destCursor = reinterpret_cast<unsigned int*>(destObject);
  unsigned int* sourceCursor = reinterpret_cast<unsigned int*>(this);
  unsigned int dwordCount = payloadSize >> 2;
  unsigned int byteRemainder = payloadSize & 3;
  unsigned int dwordIndex;
  for (dwordIndex = dwordCount; dwordIndex != 0; dwordIndex = dwordIndex - 1) {
    *destCursor = *sourceCursor;
    sourceCursor = sourceCursor + 1;
    destCursor = destCursor + 1;
  }
  unsigned char* destByteCursor = reinterpret_cast<unsigned char*>(destCursor);
  unsigned char* sourceByteCursor = reinterpret_cast<unsigned char*>(sourceCursor);
  for (; byteRemainder != 0; byteRemainder = byteRemainder - 1) {
    *destByteCursor = *sourceByteCursor;
    sourceByteCursor = sourceByteCursor + 1;
    destByteCursor = destByteCursor + 1;
  }
  return destObject;
}
// SYNTHETIC: IMPERIALISM 0x0055e660
// TZone::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055e6e0
// TZone::GetRuntimeClass

IMPLEMENT_DYNCREATE(TZone, TObject)

// FUNCTION: IMPERIALISM 0x0055e700
TZone::TZone()
    : field04(-1), displayName(), field0c(-1), field10(0), field12(-1), field14(0),
      prev18(static_cast<TZone*>(g_pMapActionContextListHead)), next1c(0), field20(-1),
      primaryNeighbors(), secondaryNeighbors(), field44(0) {
  field14 = static_cast<short>(g_nMapActionContextCount);
  g_nMapActionContextCount = g_nMapActionContextCount + 1;
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
  return field44 > 0;
}

// FUNCTION: IMPERIALISM 0x0055e8e0
TZone** TZonePrimaryNeighborStretch::GetOrAppendUnique(TZone* zone) {
  int count = GetSize();
  for (int index = 0; index < count; ++index) {
    if (GetAt(index) == zone) {
      return &ElementAt(index);
    }
  }
  Add(zone);
  return &ElementAt(count);
}

// FUNCTION: IMPERIALISM 0x0055e9c0
TZone** TZoneSecondaryNeighborStretch::GetOrAppendUnique(TZone* zone) {
  int count = GetSize();
  for (int index = 0; index < count; ++index) {
    if (GetAt(index) == zone) {
      return &ElementAt(index);
    }
  }
  Add(zone);
  return &ElementAt(count);
}

// FUNCTION: IMPERIALISM 0x0055ead0
void TZonePrimaryNeighborStretch::Add(TZone* zone) {
  AppendZonePointerToStretch(this, zone);
}

// FUNCTION: IMPERIALISM 0x0055eba0
void TZoneSecondaryNeighborStretch::Add(TZone* zone) {
  AppendZonePointerToStretch(this, zone);
}

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
void TZone::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x0055eff0
void TZone::WriteTo(TStream* stream) {}

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
  return field14;
}

// FUNCTION: IMPERIALISM 0x0055f100
TZone* FindMapActionContextByNodeId(short nodeId) {
  if (nodeId == -1) {
    return 0;
  }
  TZone* node;
  for (node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
    // Original inlines GetContextOrdinalOrInvalid (null -> -1, unreachable here).
    short ordinal = (node != 0) ? node->field14 : -1;
    if (ordinal == nodeId) {
      break;
    }
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x0055f300
void TZone::AppendUniquePrimaryNeighbor(TZone* zone) {
  primaryNeighbors.GetOrAppendUnique(zone);
}

// FUNCTION: IMPERIALISM 0x0055f5c0
void TZone::GenerateZoneStatusCodeIfUnset() {
  if (field04 != -1) {
    return; // status code already assigned
  }
  short category;
  if (QueryPortZoneCapability() != 0) {
    category = 5; // port zones are always the highest status band
  } else {
    category = static_cast<short>(primaryNeighbors.Count());
    if (category == 2) {
      // Materialize the primary-neighbor storage to hold at least 2 entries, growing
      // its raw block (realloc-to-double, fall back to exact) exactly as the original.
      // The original calls the cdecl allocator directly, so cast at the callsite.
      if (static_cast<unsigned int>(primaryNeighbors.Capacity()) < 2) {
        void* grown = reinterpret_cast<void*(__cdecl*)(void*, int)>(
            ReallocateHeapBlockWithAllocatorTracking)(primaryNeighbors.Data(), 0x10);
        if (grown == 0) {
          primaryNeighbors.Data() =
              static_cast<TZone**>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
                  ReallocateHeapBlockWithAllocatorTracking)(primaryNeighbors.Data(), 8));
          primaryNeighbors.Capacity() = 2;
        } else {
          primaryNeighbors.Data() = static_cast<TZone**>(grown);
          primaryNeighbors.Capacity() = 4;
        }
      }
      if (static_cast<unsigned int>(primaryNeighbors.Count()) < 2) {
        primaryNeighbors.Count() = 2;
      }
      if (primaryNeighbors.Capacity() == 0) {
        void* grown = reinterpret_cast<void*(__cdecl*)(void*, int)>(
            ReallocateHeapBlockWithAllocatorTracking)(primaryNeighbors.Data(), 8);
        if (grown == 0) {
          primaryNeighbors.Data() =
              static_cast<TZone**>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
                  ReallocateHeapBlockWithAllocatorTracking)(primaryNeighbors.Data(), 4));
          primaryNeighbors.Capacity() = 1;
        } else {
          primaryNeighbors.Data() = static_cast<TZone**>(grown);
          primaryNeighbors.Capacity() = 2;
        }
      }
      if (primaryNeighbors.Count() == 0) {
        primaryNeighbors.Count() = 1;
      }
      // Is the second primary neighbor also a primary neighbor of the first? If so the
      // two share an edge and the context sits inside a cluster (category 1).
      TZone* neighbor0 = primaryNeighbors.Data()[0];
      unsigned int neighborCount = static_cast<unsigned int>(neighbor0->primaryNeighbors.Count());
      if (neighborCount != 0) {
        TZone** scan = neighbor0->primaryNeighbors.Data();
        TZone* target = primaryNeighbors.Data()[1];
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
  field04 = static_cast<short>(((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 3) + category * 4);
}

// FUNCTION: IMPERIALISM 0x0055f780
void TZone::GenerateMapActionContextDisplayNameAndHeadline(void* usedCityFlags,
                                                           void* overrideName) {
  char* usedCity = static_cast<char*>(usedCityFlags);
  char* providedName = static_cast<char*>(overrideName);
  if (providedName == 0) {
    int chosenCity = -1;
    // With a used-city bitmap and secondary neighbours, try to feature a random adjacent
    // city that has not been used yet. The secondary list holds city score records here.
    if (usedCity != 0 && secondaryNeighbors.Count() != 0) {
      g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
      unsigned int pick = (g_zoneStatusCodePrngSeed_006a5aec >> 0xc & 0x7fff) %
                          static_cast<unsigned int>(secondaryNeighbors.Count());
      if (static_cast<unsigned int>(secondaryNeighbors.Capacity()) <= pick) {
        secondaryNeighbors.ResizePointerArrayCapacityByRequestedCount(pick + 1);
      }
      if (static_cast<unsigned int>(secondaryNeighbors.Count()) <= pick) {
        secondaryNeighbors.Count() = pick + 1;
      }
      TGlobalMapCityScoreRecord* cityRecord = static_cast<TGlobalMapCityScoreRecord*>(
          static_cast<void*>(secondaryNeighbors.Data()[pick]));
      short tile = cityRecord->linkedRegionIds[0];
      chosenCity = g_pGlobalMapState->terrainStateTable[tile].cityRecordIndex;
      if (usedCity[chosenCity] == '\0') {
        usedCity[chosenCity] = 1;
      } else {
        chosenCity = -1;
      }
    }
    if (chosenCity == -1) {
      if (g_pLocalizationTable->useLocalizedNameTables68 == '\0') {
        GenerateMappedFlavorTextByCurrentContextNation(&displayName);
      } else {
        // Walk the headline resource table with a random start + stride so successive
        // contexts get distinct names.
        if (g_mapActionContextDisplayNameCacheId_006984b8 == -1) {
          unsigned int r = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
          g_mapActionContextDisplayNameCacheId_006984b8 = (r >> 0xc & 0x7fff) % 0x25;
          g_zoneStatusCodePrngSeed_006a5aec = r * 0x15a4e35 + 1;
          int strides[4] = {1, 7, 0xb, 0x17};
          g_mapActionContextDisplayNameCacheStep_006984bc =
              strides[g_zoneStatusCodePrngSeed_006a5aec >> 0xc & 3];
        }
        CString resourceName;
        g_pLocalizationTable->GetString(
            0x275b, static_cast<short>(g_mapActionContextDisplayNameCacheId_006984b8),
            &resourceName);
        displayName = resourceName;
        g_mapActionContextDisplayNameCacheId_006984b8 +=
            g_mapActionContextDisplayNameCacheStep_006984bc;
        if (0x24 < g_mapActionContextDisplayNameCacheId_006984b8) {
          g_mapActionContextDisplayNameCacheId_006984b8 -= 0x25;
        }
      }
    } else {
      g_pGlobalMapState->AssignSharedStringFromIndexedA8EntryNameField(chosenCity, &displayName);
    }
  } else {
    CString provided(providedName);
    displayName = provided;
  }
  // Build the headline by expanding the status-code-selected template with the display name.
  CString headlineTemplate;
  g_pLocalizationTable->GetString(0x275a, field04, &headlineTemplate);
  CString expanded;
  scanBracketExpressions(g_pLocalizationTable, &expanded, headlineTemplate, displayName);
  displayName = expanded;
}

// FUNCTION: IMPERIALISM 0x0055fae0
void TZoneSecondaryNeighborStretch::ResizePointerArrayCapacityByRequestedCount(int count) {
  unsigned int doubled = static_cast<unsigned int>(count * 2);
  if (doubled > 0x7fffffff) {
    doubled = 0x7fffffff;
  }
  void* grown = ReallocateStretchEntries(Data(), count * 8);
  if (grown == 0) {
    Data() = static_cast<TZone**>(ReallocateStretchEntries(Data(), count * 4));
    Capacity() = count;
    return;
  }
  Data() = static_cast<TZone**>(grown);
  Capacity() = static_cast<int>(doubled);
}

// FUNCTION: IMPERIALISM 0x0055fb60
void TZone::SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex) {
  field12 = static_cast<short>(nationSeedId);
  unsigned short resolvedTile = static_cast<unsigned short>(tileIndex);
  if (resolvedTile == 0xffff) {
    resolvedTile = static_cast<unsigned short>(
        g_pGlobalMapState->ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(
            static_cast<short>(nationSeedId), 0));
  }
  field0c = static_cast<int>(static_cast<short>(resolvedTile));
  field20 = static_cast<short>(field0c);
  if (QueryPortZoneCapability() != 0) {
    SetMapTileStateByteAndNotifyObserver(field20, -0xe);
    return;
  }
  SetMapTileStateByteAndNotifyObserver(field20, -0x10);
  field20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(field20, 5);
  SetMapTileStateByteAndNotifyObserver(field20, -0x12);
  field20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(field20, 0);
  SetMapTileStateByteAndNotifyObserver(field20, -0x14);
}

// FUNCTION: IMPERIALISM 0x0055fe60
short TZone::FindNearestActiveSeaContextTileFromOffset216() {
  short stepSign = 1;
  short tileIndex = static_cast<short>(field0c + 0xd8);
  short stepMagnitude = 1;
  for (;;) {
    TTerrainStateRecordView& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (static_cast<signed char>(tileRecord.pad16) == static_cast<signed char>(-1)) {
      short nationId = static_cast<short>(tileRecord.ownerNationTag04);
      TZone* contextZone = 0;
      if (nationId >= 0x17 && g_pActiveMapOrderContext != 0) {
        contextZone =
            g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(nationId);
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
  short tileIndex = static_cast<short>(field0c);
  short stepSign = 1;
  short stepMagnitude = 1;
  for (;;) {
    TTerrainStateRecordView& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (static_cast<signed char>(tileRecord.pad16) == static_cast<signed char>(-1)) {
      short nationId = static_cast<short>(tileRecord.ownerNationTag04);
      TZone* contextZone = 0;
      if (nationId >= 0x17 && g_pActiveMapOrderContext != 0) {
        contextZone =
            g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(nationId);
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
                                                          int contextCityState) {
  TTerrainStateRecordView& tileRecord =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)];
  if (tileRecord.pad00[0] != 5) {
    return 0;
  }
  if (static_cast<signed char>(tileRecord.pad16) != static_cast<signed char>(-1)) {
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
      if (neighborRecord.pad00[0] == 5) {
        signed char neighborSubtype = static_cast<signed char>(neighborRecord.pad16);
        if ((neighborSubtype == 3) || (neighborSubtype == 0x0e)) {
          TZone* portZone = TZone::FindPortZoneByTile(neighborTile);
          if (portZone != contextZone) {
            score = score - 1;
          }
        } else {
          short cityStateLink = neighborRecord.cityRecordIndex;
          TGlobalMapCityScoreRecord* cityStateRecord = 0;
          if (cityStateLink != -1) {
            cityStateRecord = &g_pGlobalMapState->cityScoreTable[cityStateLink];
          }
          if (reinterpret_cast<int>(cityStateRecord) == contextCityState) {
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
short TZone::FindBestCoastalTileForContextAndCityStateByHeuristic(int contextCityState) {
  unsigned int tileCandidate = 0;

  for (;;) {
    TTerrainStateRecordView& tileRecord =
        g_pGlobalMapState->terrainStateTable[static_cast<short>(tileCandidate)];
    if (tileRecord.pad00[0] == 5) {
      TZone* zoneForTile = 0;
      if (g_pActiveMapOrderContext != 0) {
        zoneForTile =
            g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(static_cast<short>(tileCandidate));
      }
      if (zoneForTile == this) {
        int neighborDir = 0;
        do {
          short neighborTile = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(
              static_cast<short>(tileCandidate), static_cast<short>(neighborDir));
          if (neighborTile != -1) {
            TTerrainStateRecordView& neighborRecord =
                g_pGlobalMapState->terrainStateTable[neighborTile];
            if (neighborRecord.pad00[0] != 5) {
              short cityStateLink = neighborRecord.cityRecordIndex;
              TGlobalMapCityScoreRecord* cityStateRecord = 0;
              if (cityStateLink != -1) {
                cityStateRecord = &g_pGlobalMapState->cityScoreTable[cityStateLink];
              }
              if (reinterpret_cast<int>(cityStateRecord) == contextCityState) {
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
    tileCandidate = tileCandidate + 1;
    if (static_cast<short>(tileCandidate) >= 0x1950) {
      break;
    }
  }

  if (static_cast<short>(tileCandidate) > 0x194f) {
    tileCandidate = static_cast<unsigned short>(static_cast<short>(field0c) + 0x6c);
  }

  short bestTile = static_cast<short>(tileCandidate);
  int bestTileIndex = static_cast<int>(bestTile);
  int bestScore =
      ScoreCoastalTileForContextAndCityStateAffinity(bestTileIndex, this, contextCityState);

  HexSpiralSearchState spiral;
  spiral.row = bestTileIndex / 0x6c;
  spiral.col = bestTileIndex % 0x6c;
  spiral.ring = 0;
  spiral.direction = 5;
  spiral.stepInRing = 1;
  TMapMgr::AdvanceSpiralSearchStateAndStepHexCoordinates(&spiral);

  while (spiral.ring < 0xc) {
    short spiralTile = TMapMgr::TileIndexFromRowCol(spiral.row, spiral.col);

    bool tileInBounds;
    if ((spiralTile < 0) || (0x194f < spiralTile)) {
      tileInBounds = false;
    } else {
      tileInBounds = true;
    }

    if (tileInBounds) {
      int spiralTileIndex = TMapMgr::TileIndexFromRowCol(spiral.row, spiral.col);
      int candidateScore =
          ScoreCoastalTileForContextAndCityStateAffinity(spiralTileIndex, this, contextCityState);
      if (bestScore < candidateScore) {
        bestScore = candidateScore;
        short nextTile = TMapMgr::TileIndexFromRowCol(spiral.row, spiral.col);
        if (nextTile < 0) {
          tileCandidate = 0xffffffff;
        } else {
          tileCandidate = static_cast<unsigned int>(nextTile);
        }
      }
    }

    bestTile = static_cast<short>(tileCandidate);
    spiral.stepInRing = spiral.stepInRing + 1;
    if (spiral.ring <= spiral.stepInRing) {
      spiral.stepInRing = 0;
      spiral.direction = spiral.direction + 1;
      if (5 < spiral.direction) {
        spiral.ring = spiral.ring + 1;
        spiral.direction = 0;
        TMapMgr::StepHexRowColByDirectionWithWrapRules(&spiral.row, &spiral.col, 4);
      }
    }
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&spiral.row, &spiral.col, spiral.direction);
  }

  return bestTile;
}

// FUNCTION: IMPERIALISM 0x00560580
void TZone::SetMapOrderUiFlag(int flag) {
  unsigned char tileStateByte = g_pGlobalMapState->terrainStateTable[field20].pad16;
  if (((static_cast<unsigned char>(flag != 0) !=
        static_cast<unsigned char>(static_cast<signed char>(tileStateByte) < 0 ? 1 : 0)) &&
       (g_pUiRuntimeContext != 0)) &&
      (g_pUiRuntimeContext->mapUberPictureF0 != 0)) {
    char sign = static_cast<char>((-(static_cast<int>(flag != 0)) & 2) - 1);
    if (QueryPortZoneCapability() != 0) {
      SetMapTileStateByteAndNotifyObserver(field20, static_cast<int>(sign) * 0xe);
      NotifyMapUberPictureTileMarker(field20);
      return;
    }
    int magnitude = static_cast<int>(sign);
    SetMapTileStateByteAndNotifyObserver(field20, magnitude << 4);
    NotifyMapUberPictureTileMarker(field20);
    field20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(field20, 5);
    SetMapTileStateByteAndNotifyObserver(field20, magnitude * 0x12);
    NotifyMapUberPictureTileMarker(field20);
    field20 = g_pGlobalMapState->StepHexTileIndexByDirectionWithWrapRules(field20, 0);
    SetMapTileStateByteAndNotifyObserver(field20, magnitude * 0x14);
    NotifyMapUberPictureTileMarker(field20);
  }
}

// FUNCTION: IMPERIALISM 0x00560f80
void TZone::PropagateMapActionContextDistanceLevelsRecursive(short level) {
  if (level == -1) {
    for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
      node->field44 = 0x29a;
    }
    level = 0;
  }
  if (level < field44) {
    field44 = level;
    for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
      primaryNeighbors.EnsureCapacityAtLeast(i + 1);
      if (primaryNeighbors.Count() <= i) {
        primaryNeighbors.Count() = i + 1;
      }
      TZone* neighbor = primaryNeighbors.GetAt(i);
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

  short thisOrd = GetContextOrdinalOrInvalid();
  short otherOrd = other->GetContextOrdinalOrInvalid();
  char* cache = static_cast<char*>(g_pMapActionContextDistanceCache);
  signed char cachedDistance = cache[thisOrd * g_nMapActionContextCount + otherOrd];

  if (cachedDistance < 0) {
    for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
      node->field44 = 0x29a;
    }

    if (field44 > 0) {
      field44 = 0;
      for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
        primaryNeighbors.EnsureCapacityAtLeast(i + 1);
        if (primaryNeighbors.Count() <= i) {
          primaryNeighbors.Count() = i + 1;
        }
        TZone* neighbor = primaryNeighbors.GetAt(i);
        neighbor->PropagateMapActionContextDistanceLevelsRecursive(1);
      }
    }

    for (TZone* writeNode = g_pMapActionContextListHead; writeNode != 0;
         writeNode = writeNode->prev18) {
      short nodeOrd = writeNode->GetContextOrdinalOrInvalid();
      cache = static_cast<char*>(g_pMapActionContextDistanceCache);
      cache[thisOrd * g_nMapActionContextCount + nodeOrd] = static_cast<char>(writeNode->field44);
      cache[nodeOrd * g_nMapActionContextCount + thisOrd] = static_cast<char>(writeNode->field44);
    }

    cache = static_cast<char*>(g_pMapActionContextDistanceCache);
    cachedDistance = cache[thisOrd * g_nMapActionContextCount + otherOrd];
  }

  return static_cast<unsigned char>(cachedDistance);
}

// FUNCTION: IMPERIALISM 0x00561300
void TZonePrimaryNeighborStretch::EnsureCapacityAtLeast(int count) {
  unsigned int doubledCapacity = static_cast<unsigned int>(count * 2);
  if (doubledCapacity > 0x7fffffffU) {
    doubledCapacity = 0x7fffffffU;
  }
  void* grownBuffer = ReallocateStretchEntries(Data(), count * 8);
  if (grownBuffer == 0) {
    Data() = static_cast<TZone**>(ReallocateStretchEntries(Data(), count * 4));
    Capacity() = count;
  } else {
    Data() = static_cast<TZone**>(grownBuffer);
    Capacity() = static_cast<int>(doubledCapacity);
  }
}

// FUNCTION: IMPERIALISM 0x00561bf0
TZone* TZone::FindPortZoneByTile(short nTileIndex) {
  for (TZone* zone = TZone::GetFirstPortZone(); zone != 0; zone = zone->GetNextPortZone()) {
    if (static_cast<short>(zone->field0c) == nTileIndex || zone->field20 == nTileIndex ||
        static_cast<short>(static_cast<TPortZone*>(zone)->field48) == nTileIndex) {
      return zone;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00561c80
TZone* TZone::GetFirstPortZone() {
  TZone* cursor = g_pMapActionContextListHead;
  while (cursor != 0 && cursor->QueryPortZoneCapability() == 0) {
    cursor = cursor->prev18;
  }
  return cursor;
}

// FUNCTION: IMPERIALISM 0x00561d40
TZone* TZone::GetNextPortZone() {
  TZone* cursor = this->prev18;
  while (cursor != 0 && cursor->QueryPortZoneCapability() == 0) {
    cursor = cursor->prev18;
  }
  return cursor;
}

// Destructors are compiler-generated (implicit virtual dtor).
// PortZone vtable bodies (0x005616c0..0x00561e40) live in TPortZone.cpp.

// SYNTHETIC: IMPERIALISM 0x00562880
// TZone::`vector deleting destructor'
TZone::~TZone() {}

// Reseeds the zone status-code PRNG from a hash of the scenario tag string (falling back
// to the wall clock when the tag hashes to zero), then walks the whole map-action-context
// list assigning each zone a status code and refreshing its display name/headline.
// FUNCTION: IMPERIALISM 0x00563220
void RegenerateAllMapActionContextStatusCodes(void) {
  char* tag = g_pGlobalMapState->scenarioTagText1c;
  int seed = 0x6e616461;
  while (*tag != '\0') {
    seed = (seed >> 0x10) + seed * 2 + static_cast<int>(*tag);
    tag = tag + 1;
  }
  g_zoneStatusCodePrngSeed_006a5aec = seed;
  if (seed == 0) {
    g_zoneStatusCodePrngSeed_006a5aec =
        reinterpret_cast<int(__cdecl*)(void*)>(GetCurrentLocalEpochSecondsWithTimezoneCache)(0);
  }
  g_mapActionContextDisplayNameCacheId_006984b8 = -1;

  int statusScratch[96];
  for (int i = 0; i < 0x60; i = i + 1) {
    statusScratch[i] = 0;
  }

  for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prev18) {
    node->GenerateZoneStatusCodeIfUnset();
    node->GenerateMapActionContextDisplayNameAndHeadline(statusScratch, 0);
  }

  g_zoneStatusCodePrngSeed_006a5aec = 0;
  g_zoneStatusCodePrngSeed_006a5aec =
      reinterpret_cast<int(__cdecl*)(void*)>(GetCurrentLocalEpochSecondsWithTimezoneCache)(0);
}

// FUNCTION: IMPERIALISM 0x00563540
TZone* TZone::FindFirstPortZoneContextByNation(short nationSlot) {
  TZone* esi = static_cast<TZone*>(g_pMapActionContextListHead);
  if (esi != 0) {
    do {
      if (esi->QueryPortZoneCapability() != 0) {
        break;
      }
      esi = esi->prev18;
    } while (esi != 0);
  }

  TZone* eax = esi;
  if (eax == 0) {
    return 0;
  }

  do {
    short tileIndex = static_cast<short>(static_cast<TPortZone*>(eax)->field48);
    short ownerTag =
        static_cast<short>(g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
    if (ownerTag == nationSlot) {
      return eax;
    }

    esi = eax->prev18;
    if (esi != 0) {
      do {
        if (esi->QueryPortZoneCapability() != 0) {
          break;
        }
        esi = esi->prev18;
      } while (esi != 0);
    }
    eax = esi;
  } while (eax != 0);

  return 0;
}

// Walks every map tile; for each coastal/port tile (terrain marker 3 or 0xe) or land tile
// in a city region, resolves the owning map-action context (a port zone matched by tile id,
// or the region-indexed context) and, for each of the tile's 6 hex neighbours that carries a
// city record, adds that city context to the owning context's secondary-neighbour list.
// FUNCTION: IMPERIALISM 0x00563da0
void PopulatePortZoneAdjacencyToNearbyCityContexts(void) {
  int tileIndex = 0;
  int tileByteOffset = 0;
  do {
    TZone* context;
    short marker = static_cast<signed char>(
        *(reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) + 0x16 + tileByteOffset));
    if (marker == 3 || marker == 0xe) {
      // Inlined FindPortZoneByTile(tileIndex): match a port zone by any of its tile ids.
      context = TZone::GetFirstPortZone();
      while (context != 0) {
        short ti = static_cast<short>(tileIndex);
        if (static_cast<short>(context->field0c) == ti || context->field20 == ti ||
            static_cast<short>(static_cast<TPortZone*>(context)->field48) == ti) {
          break;
        }
        context = context->GetNextPortZone();
      }
    } else {
      short region = static_cast<short>(
          *(reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) + tileByteOffset + 4));
      if (region >= 0x17) {
        context = g_pActiveMapOrderContext->contextArray + (region - 0x17);
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
          short cityIdx = *reinterpret_cast<short*>(
              reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) + 0x14 +
              neighborTile * 0x24);
          int cityRecord;
          if (cityIdx == -1) {
            cityRecord = 0;
          } else {
            cityRecord = reinterpret_cast<int>(
                reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + cityIdx * 0xa8);
          }
          if (cityRecord != 0) {
            // Append the neighbour's city context to the secondary list if not already present.
            int* match = 0;
            if (context->secondaryNeighbors.Count() != 0) {
              int* entries = reinterpret_cast<int*>(context->secondaryNeighbors.Data());
              unsigned int j = 0;
              int* scan = entries;
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
              context->secondaryNeighbors.GetOrAppendUnique(reinterpret_cast<TZone*>(cityRecord));
            }
          }
        }
        direction = direction + 1;
      } while (direction < 6);
    }

    tileIndex = tileIndex + 1;
    tileByteOffset = tileByteOffset + 0x24;
  } while (static_cast<short>(tileIndex) < 0x1950);
}
