// TCivDescription wrapper class pair extracted from Ghidra autogen.

#include <new>

#include "decomp_types.h"
#include "game/Point32.h"
#include "game/TCivDescription.h"
#include <string.h>
#include "game/TCivilianOrderState.h"
#include "game/TGlobalMapState.h"
#include "game/TView.h"
#include "game/CString.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663118
CRuntimeClass g_pClassDescTCivDescription = {0};
}

extern "C" void* g_apTerrainTypeDescriptorTable[];
extern "C" short g_anTargetTileProfileByCivilianClassAndSlot[];
#include "game/CString.h"
#include "game/CRuntimeClass.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

undefined4 thunk_RefreshCivilianTargetLegendBySelectedClass(void);
undefined4 thunk_RenderCivilianTargetLegendVariantA(void);
undefined4 thunk_RenderCivilianTargetLegendVariantB(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);

extern "C" unsigned short g_awCivilianLegendSelectionCountsBySlot[16];
extern "C" void* g_pActiveCityDialogLegendSelectionOwner;

undefined4 InitializeUiTextStyleDescriptorAndApplyQuickDraw(void);
undefined4 thunk_MapUiThemeCodeToStyleFlags(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);

namespace {const unsigned int kAddrTargetTileProfileByCivilianClassAndSlot = 0x00698F58;
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

extern "C" __declspec(dllimport) int __stdcall PtInRect(const struct Rect32* rect,
                                                        struct Point32 point);

class ProvinceCollectionVirtualShape {
public:
  virtual void Slot00(void);
  virtual void Slot04(void);
  virtual void Slot08(void);
  virtual void Slot0c(void);
  virtual void Slot10(void);
  virtual void Slot14(void);
  virtual void Slot18(void);
  virtual void Slot1c(void);
  virtual void Slot20(void);
  virtual int GetByOrdinal(int provinceOrdinal);
  virtual int GetCount(void);
};

typedef int(__fastcall* ProvinceCollectionGetCountFn)(void* thisCollection, int unusedEdx);
typedef int(__fastcall* ProvinceCollectionGetByOrdinalFn)(void* thisCollection, int unusedEdx,
                                                          int provinceOrdinal);
typedef void(__fastcall* UiRootOnLegendTileSelectedFn)(void* thisLegendSelectionOwner,
                                                       int unusedEdx, int tileIndex);
typedef void(__cdecl* LocalizationFormatFn)(int tokenId, int arg, void* outTextRef);

} // namespace

// FUNCTION: IMPERIALISM 0x0058f050
CivDescriptionState* __cdecl CreateTCivDescriptionInstance(void) {
  return new TCivDescription();
}

TCivDescription::TCivDescription() : TControl() {
  selectedCivilianClass = -1;
  legendInitialized = 0;
}

// The ordinary destructor and the scalar deleting destructor below are both
// compiler-generated (implicit) from real inheritance — never hand-written.
// SYNTHETIC: IMPERIALISM 0x00407f4a
// TCivDescription::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058f0f0
CRuntimeClass* TCivDescription::GetRuntimeClass() {
  return &g_pClassDescTCivDescription;
}

/* Caches civilian class changes and refreshes target tile counts for supported civilian classes. */

// FUNCTION: IMPERIALISM 0x0058f110
#pragma optimize("y", on)
void TCivDescription::UpdateCivilianOrderClassAndRefreshTargetCounts(
    TCivilianOrderState* orderState) {
  TCivDescription* context = this;
  // ORIG_CALLCONV: __thiscall
  short civilianClassId;
  if (orderState == 0) {
    context->selectedCivilianClass = (short)-1;
    return;
  }
  civilianClassId = orderState->civilianClassId;
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
#pragma optimize("y", on)
void TCivDescription::HandleCivilianLegendHitTestAndSelectOrder(int arg1, int arg2, Point32* point,
                                                                int arg4) {
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
    if (PtInRect(legendRect, *point) != 0) {
      ProvinceCollectionVirtualShape* ownerNationProvinceCollection =
          *reinterpret_cast<ProvinceCollectionVirtualShape**>(
              *reinterpret_cast<int*>(reinterpret_cast<char*>(g_apTerrainTypeDescriptorTable) +
                                      this->ownerNationId * 4) +
              0x90);
      provinceCount = ownerNationProvinceCollection->GetCount();
      if (0 < provinceCount) {
        provinceOrdinal = 1;
        do {
          provinceId = ownerNationProvinceCollection->GetByOrdinal(provinceOrdinal);
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
#pragma optimize("", on)

#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x0058f3c0
void TCivDescription::UpdateCivilianOrderTargetTileCountsForOwnerNation(
    TCivilianOrderState* orderState) {
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
  ProvinceCollectionVirtualShape* ownerNationProvinceCollection;
  int provinceCount;

  provinceOrdinal = 1;
  ownerNationId = (short)*(char*)(reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) +
                                  4 + orderState->currentTileIndex * 0x24);
  context->ownerNationId = ownerNationId;
  ownerNationProvinceCollection = *reinterpret_cast<ProvinceCollectionVirtualShape**>(
      reinterpret_cast<char*>(g_apTerrainTypeDescriptorTable[ownerNationId]) + 0x90);
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
    int provinceRecordId = ownerNationProvinceCollection->GetByOrdinal(provinceOrdinal);
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
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x0058f550
#pragma optimize("y", on)
void TCivDescription::RefreshCivilianTargetLegendBySelectedClass() {
  // ORIG_CALLCONV: __thiscall
  int slotIndex;
  unsigned short* legendSelectionCountsBySlot;
  int stylePrimary;
  int styleSecondary;
  CString localizedTextRef;
  void** localizationTable;
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
    this->DispatchPictureResourceCommand(0, 0, 0, 0);
  } else if (selectedClass == kCivilianClass_Engineer) {
    int boundsBuffer[4];
    this->SwitchTab(boundsBuffer);
  } else if (selectedClass != kCivilianClass_Developer) {
    this->AssertCityProductionGlobalStateInitialized(0, 0);
  }

  this->legendInitialized = 1;
  if (selectedClass != (short)-1) {
    stylePrimary = 0;
    styleSecondary = 0;

    reinterpret_cast<void(__cdecl*)(int, int, int)>(
        InitializeUiTextStyleDescriptorAndApplyQuickDraw)(0, 0xc, 0x2b68);
    reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
        0x2b6c, reinterpret_cast<int>(&stylePrimary));
    reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
        0x2b67, reinterpret_cast<int>(&styleSecondary));
    localizationTable = *reinterpret_cast<void***>(kAddrLocalizationTable);
    reinterpret_cast<LocalizationFormatFn>(localizationTable[0x21])(
        0x2718, selectedClass, reinterpret_cast<int*>(&localizedTextRef));

    textWidth = static_cast<short>(
        reinterpret_cast<int(__cdecl*)(void)>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)());
    textOriginX = static_cast<short>((this->field34 / 2) - (textWidth / 2));

    SetQuickDrawColorAndSyncGlobals();
    reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
        static_cast<short>(textOriginX + 1), 0x47);
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        reinterpret_cast<int*>(&localizedTextRef), 0);
    SetQuickDrawColorAndSyncGlobals();
    reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
        textOriginX, 0x46);
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        reinterpret_cast<int*>(&localizedTextRef), 0);
  }
}

// FUNCTION: IMPERIALISM 0x0058f7b0
void TCivDescription::RenderCivilianTargetLegendVariantA() {
  TCivDescription* context = this;
  // ORIG_CALLCONV: __thiscall

  reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderCivilianTargetLegendVariantA)(context);
}

// FUNCTION: IMPERIALISM 0x0058fec0
void __cdecl RenderCivilianTargetLegendVariantB(void) {
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RenderCivilianTargetLegendVariantB)();
}
