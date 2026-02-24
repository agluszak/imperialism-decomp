// TCivDescription wrapper class pair extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TView.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_UpdateCivilianOrderTargetTileCountsForOwnerNation(void);
undefined4 thunk_RefreshCivilianTargetLegendBySelectedClass(void);
undefined4 thunk_RenderCivilianTargetLegendVariantA(void);
undefined4 thunk_RenderCivilianTargetLegendVariantB(void);
int* InitializeSharedStringRefFromEmpty(int* dst_ref_ptr);
void ReleaseSharedStringRefIfNotEmpty(int* ref_ptr);
undefined4 InitializeUiTextStyleDescriptorAndApplyQuickDraw(void);
undefined4 thunk_MapUiThemeCodeToStyleFlags(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);

namespace {

// GLOBAL: IMPERIALISM 0x668130
char g_vtblTCivDescription;
// GLOBAL: IMPERIALISM 0x663118
char g_pClassDescTCivDescription;
const unsigned int kAddrTargetTileProfileByCivilianClassAndSlot = 0x00698F58;
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrGlobalUiRootController = 0x006A1344;
const unsigned int kAddrLocalizationTable = 0x006A20F8;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kAddrCivilianLegendSelectionCountsBySlot = 0x006A4490;

struct CivDescriptionState {
  void* vftable;
  unsigned char pad_04_to_5f[0x5c];
  short selectedCivilianClass;
  unsigned char pad_62_to_6b[0x0a];
  unsigned char legendInitialized;
  unsigned char pad_6d_to_6f[0x03];
  unsigned char pad_70_to_16f[0x100];
};

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

struct TCivilianOrderState {
  void* vftable;
  short eCivilianClassId;
  short nCurrentTileIndex;
};

struct CivilianClassCacheContext {
  void* vftable;
  unsigned char pad_04_to_5f[0x5c];
  short cachedCivilianClassId;
  short ownerNationId;
  unsigned char pad_64_to_6f[0x0c];
};

struct Point32 {
  int x;
  int y;
};

struct Rect32 {
  int left;
  int top;
  int right;
  int bottom;
};

extern "C" int __stdcall PtInRect(const Rect32* rect, Point32 point);

typedef int(__fastcall* ProvinceCollectionGetCountFn)(void* thisCollection, int unusedEdx);
typedef int(__fastcall* ProvinceCollectionGetByOrdinalFn)(void* thisCollection, int unusedEdx,
                                                          int provinceOrdinal);
typedef void(__fastcall* UiRootOnLegendTileSelectedFn)(void* thisLegendSelectionOwner,
                                                       int unusedEdx, int tileIndex);
typedef void(__cdecl* LocalizationFormatFn)(int tokenId, int arg, void* outTextRef);

} // namespace

void __fastcall
UpdateCivilianOrderTargetTileCountsForOwnerNation(CivilianClassCacheContext* context, int unusedEdx,
                                                  TCivilianOrderState* orderState);

// FUNCTION: IMPERIALISM 0x0058f050
CivDescriptionState* __cdecl CreateTCivDescriptionInstance(void) {
  CivDescriptionState* civDescription =
      reinterpret_cast<CivDescriptionState*>(AllocateWithFallbackHandler(0x170));
  if (civDescription != 0) {
    reinterpret_cast<TView*>(civDescription)->thunk_ConstructUiResourceEntryBase();
    civDescription->vftable = reinterpret_cast<void*>(&g_vtblTCivDescription);
    civDescription->selectedCivilianClass = -1;
    civDescription->legendInitialized = 0;
  }
  return civDescription;
}

// FUNCTION: IMPERIALISM 0x0058f0f0
void* __cdecl GetTCivDescriptionClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCivDescription);
}

/* Caches civilian class changes and refreshes target tile counts for supported civilian classes. */

// FUNCTION: IMPERIALISM 0x0058f110
void __fastcall UpdateCivilianOrderClassAndRefreshTargetCounts(CivilianClassCacheContext* context,
                                                               int unusedEdx,
                                                               TCivilianOrderState* orderState) {
  // ORIG_CALLCONV: __thiscall
  short civilianClassId;

  (void)unusedEdx;
  if (orderState == 0) {
    context->cachedCivilianClassId = (short)-1;
    return;
  }
  civilianClassId = orderState->eCivilianClassId;
  if (civilianClassId != context->cachedCivilianClassId) {
    context->cachedCivilianClassId = civilianClassId;
    switch ((ECivilianClassId)civilianClassId) {
    case kCivilianClass_Miner:
    case kCivilianClass_Prospector:
    case kCivilianClass_Farmer:
    case kCivilianClass_Forester:
    case kCivilianClass_Rancher:
    case kCivilianClass_Developer:
    case kCivilianClass_Driller:
      *reinterpret_cast<unsigned char*>(reinterpret_cast<char*>(context) + 0x6c) = 0;
      reinterpret_cast<void(__fastcall*)(void*, int, TCivilianOrderState*)>(
          thunk_UpdateCivilianOrderTargetTileCountsForOwnerNation)(context, 0, orderState);
      break;
    }
    reinterpret_cast<void(__fastcall*)(void*)>(reinterpret_cast<int*>(context->vftable)[0x39])(
        context);
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

   Consumes pCivilianOrderState->nCurrentTileIndex and class-indexed target profile table. */

/* Handles civ-description click hit-test and selects matching terrain/entry descriptor. */

// FUNCTION: IMPERIALISM 0x0058f1a0
void __fastcall DestructTCivDescriptionAndMaybeFree(CivDescriptionState* context, int unusedEdx,
                                                    void* pointArg) {
  // ORIG_CALLCONV: __thiscall
  short tileIndex;
  short ownerNationId;
  int provinceTileOrdinal;
  int provinceTileCount;
  short* provinceTileIndices;
  unsigned short* legendSelectionCountsBySlot;
  int candidateOrdinal;
  Rect32* legendRect;
  int slotIndex;
  int provinceOrdinal;
  int provinceCount;
  int provinceId;
  int globalMapState;
  int tileDataBase;
  int provinceDataBase;
  int* ownerNationProvinceCollection;
  ProvinceCollectionGetCountFn getProvinceCount;
  ProvinceCollectionGetByOrdinalFn getProvinceIdByOrdinal;

  (void)unusedEdx;
  legendRect = reinterpret_cast<Rect32*>(reinterpret_cast<char*>(context) + 0x70);
  legendSelectionCountsBySlot =
      reinterpret_cast<unsigned short*>(kAddrCivilianLegendSelectionCountsBySlot);
  candidateOrdinal = 0;
  ownerNationId = *reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x62);
  slotIndex = 0;
  while (slotIndex < 0x10) {
    if (PtInRect(legendRect, *reinterpret_cast<Point32*>(pointArg)) != 0) {
      ownerNationProvinceCollection = *reinterpret_cast<int**>(
          *reinterpret_cast<int*>(kAddrTerrainTypeDescriptorTable + ownerNationId * 4) + 0x90);
      getProvinceCount =
          *reinterpret_cast<ProvinceCollectionGetCountFn>(*ownerNationProvinceCollection + 0x28);
      provinceCount = getProvinceCount(ownerNationProvinceCollection, 0);
      if (0 < provinceCount) {
        getProvinceIdByOrdinal = *reinterpret_cast<ProvinceCollectionGetByOrdinalFn>(
            *ownerNationProvinceCollection + 0x24);
        provinceOrdinal = 1;
        do {
          provinceId = getProvinceIdByOrdinal(ownerNationProvinceCollection, 0, provinceOrdinal);
          globalMapState = *reinterpret_cast<int*>(kAddrGlobalMapState);
          provinceDataBase = *reinterpret_cast<int*>(globalMapState + 0x10);
          provinceTileCount = (int)*(char*)(provinceDataBase + provinceId * 0xa8 + 0x3a);
          if (0 < provinceTileCount) {
            tileDataBase = *reinterpret_cast<int*>(globalMapState + 0xc);
            provinceTileIndices =
                reinterpret_cast<short*>(provinceDataBase + provinceId * 0xa8 + 0x42);
            provinceTileOrdinal = 0;
            while (provinceTileOrdinal < provinceTileCount) {
              tileIndex = *provinceTileIndices;
              if ((*(char*)(tileDataBase + tileIndex * 0x24 + 0xe) == '\0') &&
                  ((unsigned short)(unsigned char)*(char*)(tileDataBase + tileIndex * 0x24 +
                                                           0x13) == (unsigned short)slotIndex)) {
                if ((int)(unsigned int)legendSelectionCountsBySlot[slotIndex] <= candidateOrdinal) {
                  void* uiRootController = *reinterpret_cast<void**>(kAddrGlobalUiRootController);
                  void* legendSelectionOwner =
                      *reinterpret_cast<void**>(reinterpret_cast<char*>(uiRootController) + 0x48);
                  if (legendSelectionOwner != 0) {
                    reinterpret_cast<UiRootOnLegendTileSelectedFn>(reinterpret_cast<int*>(
                        *reinterpret_cast<void**>(legendSelectionOwner))[0x78])(
                        legendSelectionOwner, 0, (int)tileIndex);
                  }
                  legendSelectionCountsBySlot[slotIndex] =
                      (unsigned short)(legendSelectionCountsBySlot[slotIndex] + 1);
                  return;
                }
                candidateOrdinal = candidateOrdinal + 1;
              }
              provinceTileOrdinal = provinceTileOrdinal + 1;
              provinceTileIndices = provinceTileIndices + 1;
            }
          }
          provinceOrdinal = provinceOrdinal + 1;
          provinceCount = getProvinceCount(ownerNationProvinceCollection, 0);
        } while (provinceOrdinal <= provinceCount);
      }
    }
    slotIndex = slotIndex + 1;
    candidateOrdinal = candidateOrdinal + 1;
    legendRect = legendRect + 1;
  }
}

// FUNCTION: IMPERIALISM 0x0058f3c0
void __fastcall
UpdateCivilianOrderTargetTileCountsForOwnerNation(CivilianClassCacheContext* context, int unusedEdx,
                                                  TCivilianOrderState* orderState) {
  // ORIG_CALLCONV: __thiscall
  short ownerNationId;
  int provinceTileOrdinal;
  int provinceRecord;
  short* targetCountSlot;
  int classSlotOrdinal;
  int provinceOrdinal;
  int provinceCount;
  short* provinceTileIndices;
  int tileRecord;
  char tileProfileId;
  int globalMapState;
  int tileDataBase;
  int provinceDataBase;
  int* ownerNationProvinceCollection;
  ProvinceCollectionGetCountFn getProvinceCount;
  ProvinceCollectionGetByOrdinalFn getProvinceIdByOrdinal;

  (void)unusedEdx;
  provinceOrdinal = 1;
  globalMapState = *reinterpret_cast<int*>(kAddrGlobalMapState);
  tileDataBase = *reinterpret_cast<int*>(globalMapState + 0xc);
  ownerNationId = (short)*(char*)(tileDataBase + 4 + orderState->nCurrentTileIndex * 0x24);
  context->ownerNationId = ownerNationId;
  ownerNationProvinceCollection = *reinterpret_cast<int**>(
      *reinterpret_cast<int*>(kAddrTerrainTypeDescriptorTable + ownerNationId * 4) + 0x90);
  *reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x6c) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x6a) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x68) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x66) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x64) = 0;
  getProvinceCount =
      *reinterpret_cast<ProvinceCollectionGetCountFn>(*ownerNationProvinceCollection + 0x28);
  provinceCount = getProvinceCount(ownerNationProvinceCollection, 0);
  if (0 < provinceCount) {
    getProvinceIdByOrdinal =
        *reinterpret_cast<ProvinceCollectionGetByOrdinalFn>(*ownerNationProvinceCollection + 0x24);
    do {
      provinceRecord = getProvinceIdByOrdinal(ownerNationProvinceCollection, 0, provinceOrdinal);
      provinceTileOrdinal = 0;
      provinceDataBase = *reinterpret_cast<int*>(globalMapState + 0x10);
      provinceRecord = provinceDataBase + provinceRecord * 0xa8;
      if ('\0' < *(char*)(provinceRecord + 0x3a)) {
        provinceTileIndices = reinterpret_cast<short*>(provinceRecord + 0x42);
        do {
          tileRecord = tileDataBase + *provinceTileIndices * 0x24;
          if (*(char*)(tileRecord + 0xe) == '\0') {
            tileProfileId = *(char*)(tileRecord + 0x13);
            classSlotOrdinal = 0;
            targetCountSlot = reinterpret_cast<short*>(reinterpret_cast<char*>(context) + 0x64);
            do {
              if ((short)tileProfileId ==
                  reinterpret_cast<short*>(kAddrTargetTileProfileByCivilianClassAndSlot)
                      [classSlotOrdinal + context->cachedCivilianClassId * 5]) {
                *targetCountSlot = (short)(*targetCountSlot + 1);
              }
              classSlotOrdinal = classSlotOrdinal + 1;
              targetCountSlot = targetCountSlot + 1;
            } while (classSlotOrdinal < 5);
          }
          provinceTileOrdinal = provinceTileOrdinal + 1;
          provinceTileIndices = provinceTileIndices + 1;
        } while (provinceTileOrdinal < *(char*)(provinceRecord + 0x3a));
      }
      provinceOrdinal = provinceOrdinal + 1;
      provinceCount = getProvinceCount(ownerNationProvinceCollection, 0);
    } while (provinceOrdinal <= provinceCount);
  }
}

// FUNCTION: IMPERIALISM 0x0058f550
void __fastcall RefreshCivilianTargetLegendBySelectedClass(CivDescriptionState* context,
                                                           int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  int slotIndex;
  unsigned short* legendSelectionCountsBySlot;
  Rect32* legendRect;
  int stylePrimary;
  int styleSecondary;
  int localizedTextRef;
  void** localizationTable;
  short selectedClass;
  short textWidth;
  short textOriginX;

  (void)unusedEdx;
  if (context->legendInitialized == 0) {
    legendSelectionCountsBySlot =
        reinterpret_cast<unsigned short*>(kAddrCivilianLegendSelectionCountsBySlot);
    legendRect = reinterpret_cast<Rect32*>(reinterpret_cast<char*>(context) + 0x70);
    for (slotIndex = 0; slotIndex < 0x10; slotIndex = slotIndex + 1) {
      legendRect[slotIndex].left = 0;
      legendRect[slotIndex].top = 0;
      legendRect[slotIndex].right = 0;
      legendRect[slotIndex].bottom = 0;
      legendSelectionCountsBySlot[slotIndex] = 0;
    }
    *reinterpret_cast<int*>(reinterpret_cast<char*>(context) + 4) = 0;
  }

  selectedClass = context->selectedCivilianClass;
  if (selectedClass == kCivilianClass_Prospector) {
    reinterpret_cast<void(__fastcall*)(void*)>(reinterpret_cast<int*>(context->vftable)[0x68])(
        context);
  } else if (selectedClass == kCivilianClass_Engineer) {
    reinterpret_cast<void(__fastcall*)(void*)>(reinterpret_cast<int*>(context->vftable)[0x69])(
        context);
  } else if (selectedClass != kCivilianClass_Developer) {
    reinterpret_cast<void(__fastcall*)(void*)>(reinterpret_cast<int*>(context->vftable)[0x6a])(
        context);
  }

  context->legendInitialized = 1;
  InitializeSharedStringRefFromEmpty(&localizedTextRef);
  if (selectedClass != (short)-1) {
    stylePrimary = 0;
    styleSecondary = 0;
    localizedTextRef = 0;

    reinterpret_cast<void(__cdecl*)(int, int, int)>(InitializeUiTextStyleDescriptorAndApplyQuickDraw)(
        0, 0xc, 0x2b68);
    reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
        0x2b6c, reinterpret_cast<int>(&stylePrimary));
    reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
        0x2b67, reinterpret_cast<int>(&styleSecondary));
    localizationTable = *reinterpret_cast<void***>(kAddrLocalizationTable);
    reinterpret_cast<LocalizationFormatFn>(localizationTable[0x21])(0x2718, selectedClass,
                                                                    &localizedTextRef);

    textWidth = static_cast<short>(
        reinterpret_cast<int(__cdecl*)(void)>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)());
    textOriginX = static_cast<short>(
        (*reinterpret_cast<int*>(reinterpret_cast<char*>(context) + 0x34) / 2) - (textWidth / 2));

    SetQuickDrawColorAndSyncGlobals();
    reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
        static_cast<short>(textOriginX + 1), 0x47);
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        &localizedTextRef, 0);
    SetQuickDrawColorAndSyncGlobals();
    reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
        textOriginX, 0x46);
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        &localizedTextRef, 0);
  }
  ReleaseSharedStringRefIfNotEmpty(&localizedTextRef);
}

// FUNCTION: IMPERIALISM 0x0058f7b0
void __fastcall RenderCivilianTargetLegendVariantA(CivDescriptionState* context, int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderCivilianTargetLegendVariantA)(context);
}

// FUNCTION: IMPERIALISM 0x0058fec0
void __cdecl RenderCivilianTargetLegendVariantB(void) {
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RenderCivilianTargetLegendVariantB)();
}
