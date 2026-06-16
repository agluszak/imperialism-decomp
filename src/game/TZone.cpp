#include "game/TZone.h"

#include "game/mfc.h"
#include "game/mfc.h"
#include "game/mfc.h"
#include "game/TGlobalMapState.h"
#include "game/TMapOrderContext.h"
#include "game/UiRuntimeContext.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern TZone* g_pMapActionContextListHead;

extern "C" {
extern int g_nMapActionContextCount;
extern void* g_pMapActionContextDistanceCache;
extern void* g_pActiveMapOrderContext;
char g_pClassDescTZone = 0;
extern char g_pClassDescTPortZone;
}

undefined4 thunk_ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(void);
undefined4 thunk_StepHexTileIndexByDirectionWithWrapRules(void);
undefined4 thunk_FindPortZoneByTile(void);
undefined4 GetNextPortZone(void);
undefined4 thunk_AdvanceSpiralSearchStateAndStepHexCoordinates(void);
undefined4 thunk_StepHexRowColByDirectionWithWrapRules(void);
undefined4 CreateObject_606ff2(void);

namespace {

void DeleteUnlinkedZone(TZone* zone) {
  delete zone;
}

} // namespace

// FUNCTION: IMPERIALISM 0x004798d0
void TZone::InvokeObjectVtableMethod24() {
  HandleTurnEventVtableSlot24CopyPayloadBuffer();
}

void* TZone::HandleTurnEventVtableSlot24CopyPayloadBuffer() {
  CRuntimeClass* runtimeClass = GetRuntimeClass();
  unsigned int payloadSize = static_cast<unsigned int>(runtimeClass->m_nObjectSize);
  GetRuntimeClass();
  CObject* destObject = reinterpret_cast<CObject*>(CreateObject_606ff2());
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

void TZone::GenerateMapActionContextDisplayNameAndHeadline(int arg1, void* arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x0055e6e0
CRuntimeClass* TZone::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTZone);
}

// FUNCTION: IMPERIALISM 0x0055e700
TZone::TZone()
    : field04(-1), field0c(-1), field10(0), field12(-1), field14(0),
      prev18(static_cast<TZone*>(g_pMapActionContextListHead)), next1c(0), field20(-1),
      portZoneEntries28(0), portZoneEntryCount2c(0), portZoneActiveEntryCount30(0), field44(0),
      field48(0), displayName() {
  field24 = reinterpret_cast<void*>(0x0065c74c);
  field38 = 0;
  field3c = 0;
  field40 = 0;
  field34 = reinterpret_cast<void*>(0x0065c748);
  field14 = static_cast<short>(g_nMapActionContextCount);
  g_nMapActionContextCount = g_nMapActionContextCount + 1;
  g_pMapActionContextListHead = this;
  if (prev18 != 0) {
    prev18->next1c = this;
  }
  if (g_pMapActionContextDistanceCache != 0) {
    FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(g_pMapActionContextDistanceCache));
    g_pMapActionContextDistanceCache = 0;
  }
}

TZone::~TZone() {}

void TZone::HandleTurnEventVtableSlot08(int arg1) {
  (void)arg1;
}

void TZone::AssertValid() const {
  return;
}

void TZone::Dump(CDumpContext& unused) const {
  (void)unused;
  return;
}

void TZone::SerializeZoneToBinaryStream(void* streamState) {
  (void)streamState;
}

void TZone::DeserializeZoneFromBinaryStream(int streamState) {
  (void)streamState;
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

// FUNCTION: IMPERIALISM 0x0055ec60
void TZone::RemoveZoneFromGlobalListAndRelease() {
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

// FUNCTION: IMPERIALISM 0x0055f070
void TZone::AssignZoneDisplayNameToOutputRef(void* outputRef) {
  (void)outputRef;
}

// FUNCTION: IMPERIALISM 0x0055f090
void TZone::AssignZoneDisplayNameAliasToOutputRef(void* outputRef) {
  (void)outputRef;
}

// FUNCTION: IMPERIALISM 0x0055fb60
void TZone::SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex) {
  field12 = static_cast<short>(nationSeedId);
  unsigned short resolvedTile = static_cast<unsigned short>(tileIndex);
  if (resolvedTile == 0xffff) {
    resolvedTile = static_cast<unsigned short>(reinterpret_cast<short(__cdecl*)(void)>(
        thunk_ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias)());
  }
  field0c = static_cast<int>(static_cast<short>(resolvedTile));
  field20 = static_cast<short>(field0c);
  if (QueryPortZoneCapability() != 0) {
    SetMapTileStateByteAndNotifyObserver(field20, -0xe);
    return;
  }
  SetMapTileStateByteAndNotifyObserver(field20, -0x10);
  field20 = reinterpret_cast<short(__cdecl*)(short, int)>(
      thunk_StepHexTileIndexByDirectionWithWrapRules)(field20, 5);
  SetMapTileStateByteAndNotifyObserver(field20, -0x12);
  field20 = reinterpret_cast<short(__cdecl*)(short, int)>(
      thunk_StepHexTileIndexByDirectionWithWrapRules)(field20, 0);
  SetMapTileStateByteAndNotifyObserver(field20, -0x14);
}

// FUNCTION: IMPERIALISM 0x0055fe60
short TZone::FindNearestActiveSeaContextTileFromOffset216() {
  short stepSign = 1;
  short tileIndex = static_cast<short>(field0c + 0xd8);
  short stepMagnitude = 1;
  for (;;) {
    char* tileRecord = reinterpret_cast<char*>(
        *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc) +
        tileIndex * 0x24);
    if (tileRecord[0x16] == static_cast<char>(-1)) {
      short nationId = static_cast<short>(tileRecord[4]);
      int contextRecord = 0;
      if (nationId >= 0x17) {
        contextRecord =
            reinterpret_cast<int>(
                static_cast<TMapOrderContext*>(g_pActiveMapOrderContext)->contextArray) +
            (nationId - 0x17) * 0x48;
      }
      if (contextRecord != 0) {
        return tileIndex;
      }
    }
    tileIndex = static_cast<short>(tileIndex + stepSign * stepMagnitude);
    stepMagnitude = static_cast<short>(stepMagnitude + 1);
    stepSign = static_cast<short>(-stepSign);
  }
}

short TZone::MapActionVtableSlot4C() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055fef0
short TZone::GetActiveNationSlotTile() {
  short tileIndex = static_cast<short>(field0c);
  short stepSign = 1;
  short stepMagnitude = 1;
  for (;;) {
    int tileRecord = *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc) +
                     tileIndex * 0x24;
    if (*reinterpret_cast<char*>(tileRecord + 0x16) == static_cast<char>(-1)) {
      short nationId = static_cast<short>(*reinterpret_cast<char*>(tileRecord + 4));
      int contextRecord = 0;
      if (nationId >= 0x17) {
        contextRecord =
            reinterpret_cast<int>(
                static_cast<TMapOrderContext*>(g_pActiveMapOrderContext)->contextArray) +
            (nationId - 0x17) * 0x48;
      }
      if (contextRecord != 0) {
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
  char* mapTileBase = reinterpret_cast<char*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc));
  char* tileRecord = mapTileBase + static_cast<short>(tileIndex) * 0x24;
  if (tileRecord[0] != static_cast<char>(0x05)) {
    return 0;
  }
  if (tileRecord[0x16] != static_cast<char>(-1)) {
    return 0;
  }
  short nationId = static_cast<short>(tileRecord[4]);
  int zoneRecord = 0;
  if (nationId >= 0x17) {
    zoneRecord = reinterpret_cast<int>(
                     static_cast<TMapOrderContext*>(g_pActiveMapOrderContext)->contextArray) +
                 (nationId - 0x17) * 0x48;
  }
  if (zoneRecord != reinterpret_cast<int>(contextZone)) {
    return 0x3e8;
  }

  int score = 0x1388;
  int neighborDir = 0;
  do {
    short neighborTile = reinterpret_cast<short(__cdecl*)(int, int)>(
        thunk_StepHexTileIndexByDirectionWithWrapRules)(tileIndex, neighborDir);
    if (neighborTile != -1) {
      char* neighborRecord = mapTileBase + neighborTile * 0x24;
      if (neighborRecord[0] == static_cast<char>(0x05)) {
        short neighborSubtype = static_cast<short>(neighborRecord[0x16]);
        if ((neighborSubtype == 3) || (neighborSubtype == 0x0e)) {
          TZone* portZone = static_cast<TZone*>(g_pMapActionContextListHead);
          while (portZone != 0 && portZone->GetRuntimeClass() !=
                                      reinterpret_cast<CRuntimeClass*>(&g_pClassDescTPortZone)) {
            portZone = portZone->prev18;
          }
          while (portZone != 0) {
            if ((static_cast<short>(portZone->field0c) == neighborTile) ||
                (portZone->field20 == neighborTile) ||
                (static_cast<short>(portZone->field48) == neighborTile)) {
              break;
            }
            portZone = static_cast<TZone*>(
                reinterpret_cast<void*(__fastcall*)(void*)>(GetNextPortZone)(portZone));
          }
          if (portZone != contextZone) {
            score = score - 1;
          }
        } else {
          short cityStateLink = *reinterpret_cast<short*>(neighborRecord + 0x14);
          int cityStateRecord = 0;
          if (cityStateLink != -1) {
            cityStateRecord =
                *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10) +
                cityStateLink * 0xa8;
          }
          if (cityStateRecord == contextCityState) {
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
  char* mapTileBase = reinterpret_cast<char*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc));
  TMapOrderContext* mapOrderContext = static_cast<TMapOrderContext*>(g_pActiveMapOrderContext);

  for (;;) {
    char* tileRecord = mapTileBase + static_cast<short>(tileCandidate) * 0x24;
    if (*tileRecord == static_cast<char>(0x05)) {
      TZone* zoneForTile = 0;
      if ((tileRecord[0x16] == static_cast<char>(0x03)) ||
          (tileRecord[0x16] == static_cast<char>(0x0e))) {
        zoneForTile = static_cast<TZone*>(reinterpret_cast<void*(__cdecl*)(short)>(
            thunk_FindPortZoneByTile)(static_cast<short>(tileCandidate)));
      } else if (static_cast<unsigned char>(tileRecord[4]) < 0x17) {
        zoneForTile = 0;
      } else {
        zoneForTile =
            reinterpret_cast<TZone*>(reinterpret_cast<int>(mapOrderContext->contextArray) +
                                     (static_cast<short>(tileRecord[4]) - 0x17) * 0x48);
      }
      if (zoneForTile == this) {
        int neighborDir = 0;
        do {
          short neighborTile = reinterpret_cast<short(__cdecl*)(unsigned int, int)>(
              thunk_StepHexTileIndexByDirectionWithWrapRules)(tileCandidate, neighborDir);
          if (neighborTile != -1) {
            char* neighborRecord = mapTileBase + neighborTile * 0x24;
            if (*neighborRecord != static_cast<char>(0x05)) {
              short cityStateLink = *reinterpret_cast<short*>(neighborRecord + 0x14);
              int cityStateRecord = 0;
              if (cityStateLink != -1) {
                cityStateRecord =
                    *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10) +
                    cityStateLink * 0xa8;
              }
              if (cityStateRecord == contextCityState) {
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

  int spiralRow = bestTileIndex / 0x6c;
  int spiralCol = bestTileIndex % 0x6c;
  int spiralRing = 0;
  int spiralDirection = 5;
  int spiralStepInRing = 1;
  reinterpret_cast<void(__fastcall*)(int*)>(thunk_AdvanceSpiralSearchStateAndStepHexCoordinates)(
      &spiralRow);

  while (spiralRing < 0xc) {
    short spiralTile;
    if (((spiralRow < 0) || (0x3b < spiralRow)) || ((spiralCol < 0) || (0x6b < spiralCol))) {
      spiralTile = -1;
    } else {
      spiralTile = static_cast<short>(spiralCol + spiralRow * 0x6c);
    }

    bool tileInBounds;
    if ((spiralTile < 0) || (0x194f < spiralTile)) {
      tileInBounds = false;
    } else {
      tileInBounds = true;
    }

    if (tileInBounds) {
      int spiralTileIndex;
      if (((spiralRow < 0) || (0x3b < spiralRow)) || ((spiralCol < 0) || (0x6b < spiralCol))) {
        spiralTileIndex = -1;
      } else {
        spiralTileIndex = spiralCol + spiralRow * 0x6c;
      }
      int candidateScore =
          ScoreCoastalTileForContextAndCityStateAffinity(spiralTileIndex, this, contextCityState);
      if (bestScore < candidateScore) {
        bestScore = candidateScore;
        if (((spiralRow < 0) || (0x3b < spiralRow)) || ((spiralCol < 0) || (0x6b < spiralCol))) {
          tileCandidate = 0xffffffff;
        } else {
          tileCandidate = static_cast<unsigned int>(spiralCol + spiralRow * 0x6c);
        }
      }
    }

    bestTile = static_cast<short>(tileCandidate);
    spiralStepInRing = spiralStepInRing + 1;
    if (spiralRing <= spiralStepInRing) {
      spiralStepInRing = 0;
      spiralDirection = spiralDirection + 1;
      if (5 < spiralDirection) {
        spiralRing = spiralRing + 1;
        spiralDirection = 0;
        reinterpret_cast<bool(__cdecl*)(int, int, int)>(
            thunk_StepHexRowColByDirectionWithWrapRules)(reinterpret_cast<int>(&spiralRow),
                                                         reinterpret_cast<int>(&spiralCol), 4);
      }
    }
    reinterpret_cast<bool(__cdecl*)(int, int, int)>(thunk_StepHexRowColByDirectionWithWrapRules)(
        reinterpret_cast<int>(&spiralRow), reinterpret_cast<int>(&spiralCol), spiralDirection);
  }

  return bestTile;
}

// FUNCTION: IMPERIALISM 0x00560580
void TZone::SetMapOrderUiFlag(int flag) {
  void** uiObserverSlot =
      g_pUiRuntimeContext != 0
          ? reinterpret_cast<void**>(reinterpret_cast<char*>(g_pUiRuntimeContext) + 0xf0)
          : 0;
  char* tileStateByte = reinterpret_cast<char*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc) + 0x16 +
      field20 * 0x24);
  if (((static_cast<unsigned char>(flag != 0) !=
        static_cast<unsigned char>(*tileStateByte < 0 ? 1 : 0)) &&
       (uiObserverSlot != 0)) &&
      (*uiObserverSlot != 0)) {
    void* uiObserver = *uiObserverSlot;
    char sign = static_cast<char>((-(static_cast<int>(flag != 0)) & 2) - 1);
    if (QueryPortZoneCapability() != 0) {
      SetMapTileStateByteAndNotifyObserver(field20, static_cast<int>(sign) * 0xe);
      reinterpret_cast<void(__fastcall*)(void*, int)>(*reinterpret_cast<int*>(
          *reinterpret_cast<int*>(uiObserver) + 0x1d8))(uiObserver, field20);
      return;
    }
    int magnitude = static_cast<int>(sign);
    SetMapTileStateByteAndNotifyObserver(field20, magnitude << 4);
    reinterpret_cast<void(__fastcall*)(void*, int)>(
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(uiObserver) + 0x1d8))(uiObserver, field20);
    field20 = reinterpret_cast<short(__cdecl*)(short, int)>(
        thunk_StepHexTileIndexByDirectionWithWrapRules)(field20, 5);
    SetMapTileStateByteAndNotifyObserver(field20, magnitude * 0x12);
    reinterpret_cast<void(__fastcall*)(void*, int)>(
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(uiObserver) + 0x1d8))(uiObserver, field20);
    field20 = reinterpret_cast<short(__cdecl*)(short, int)>(
        thunk_StepHexTileIndexByDirectionWithWrapRules)(field20, 0);
    SetMapTileStateByteAndNotifyObserver(field20, magnitude * 0x14);
    reinterpret_cast<void(__fastcall*)(void*, int)>(
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(uiObserver) + 0x1d8))(uiObserver, field20);
  }
}

namespace {

int ZoneIsPortKind(TZone* node) {
  return reinterpret_cast<CObject*>(node)->IsKindOf(
      reinterpret_cast<const CRuntimeClass*>(&g_pClassDescTPortZone));
}

} // namespace

// Destructors are compiler-generated (implicit virtual dtor).
// SYNTHETIC: IMPERIALISM 0x00562880
// TZone::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00563540
TZone* TZone::FindFirstPortZoneContextByNation(short nationSlot) {
  TZone* esi = static_cast<TZone*>(g_pMapActionContextListHead);
  if (esi != 0) {
    do {
      if (ZoneIsPortKind(esi) != 0) {
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
    int tileIndex = static_cast<int>(static_cast<short>(eax->field48));
    tileIndex = tileIndex + tileIndex * 8;
    char* terrainTable = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
    short ownerTag = static_cast<short>(static_cast<signed char>(terrainTable[tileIndex * 4 + 3]));
    if (ownerTag == nationSlot) {
      return eax;
    }

    esi = eax->prev18;
    if (esi != 0) {
      do {
        if (ZoneIsPortKind(esi) != 0) {
          break;
        }
        esi = esi->prev18;
      } while (esi != 0);
    }
    eax = esi;
  } while (eax != 0);

  return 0;
}
