#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/TMilitaryUnitOrderState.h"
#include "game/TCivWorkOrderState.h"
#include "game/TAdmiral.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TDiplomacyTurnStateManager.h"

#include "decomp_types.h"

extern "C" void* g_pActiveMapOrderContext;
extern "C" void* g_apMinorNationCapabilityObjects[];

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_FindFirstPortZoneContextByNation(void);
undefined4 thunk_CreateNavyPrimaryOrderNodeAndAssignDisplayName(void);
undefined4 thunk_SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(void);
undefined4 thunk_FindReachableRecruitSpawnTileWithVisitedReset(void);

// FUNCTION: IMPERIALISM 0x004d7770
#pragma optimize("y", on)
void TGreatPower::CreateMilitaryRecruitOrderForNode(int nodeContext) {
  int capabilityBonus = 0;
  if (static_cast<unsigned short>(this->nationSlot) < 7) {
    const TCityOrderCapabilityState::MilitaryCapRow& capabilityRow =
        CityOrderCapabilityState()->militaryCapRows39d[this->nationSlot];
    if (capabilityRow.eliteRecruitFlag != 0) {
      capabilityBonus = 0x10;
    } else {
      char capabilityFlag = static_cast<char>(capabilityRow.recruitTierFlag);
      capabilityBonus = (static_cast<int>(-capabilityFlag) >> 0x1f) & 8;
    }
  }
  TMilitaryUnitOrderState* militaryOrder = new TMilitaryUnitOrderState();
  militaryOrder->InitializeRecruitOrderState(static_cast<short>(capabilityBonus), nodeContext,
                                             this->nationSlot);
  militaryOrder->SetOrderModeSlot34(2, -1);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dab20
#pragma optimize("y", on)
void TGreatPower::ExecuteNationPendingActionStateMachine(void) {
  TCity* relationManager = this->relationManager;
  relationManager->RefreshOrderStateSlot0C();

  short nationSlot = this->nationSlot;

  // Land recruit order (serializedStatusFlags[1] == '2').
  if (this->serializedStatusFlags[1] == 0x32) {
    void* raw = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x44));
    TMilitaryUnitOrderState* militaryOrder = 0;
    if (raw != 0) {
      militaryOrder = new (raw) TMilitaryUnitOrderState();
    }
    int nodeContext = this->GetHomeRegionCityRecordIndex();
    short capValue = CityOrderCapForNation(nationSlot);
    militaryOrder->InitializeRecruitOrderState(capValue, nodeContext, nationSlot);
    this->DispatchTurnOrderActionSlotB0(3, capValue, 1);
  }

  // Navy primary/secondary order (serializedStatusFlags[0] == '2').
  if (this->serializedStatusFlags[0] == 0x32) {
    short zoneIndex = CityOrderActiveZoneIndex();
    void* portZone = reinterpret_cast<void*(__fastcall*)(void*, int, int, int)>(
        thunk_FindFirstPortZoneContextByNation)(g_pActiveMapOrderContext, nationSlot, nationSlot,
                                                0);
    reinterpret_cast<void*(__cdecl*)(int, void*, int, int)>(
        thunk_CreateNavyPrimaryOrderNodeAndAssignDisplayName)(zoneIndex, portZone, nationSlot, 0);

    ++relationManager->recruitZoneCount5c[CityOrderActiveZoneIndex()];

    void* secondaryNode = new TAdmiral(nationSlot);
    reinterpret_cast<void(__fastcall*)(void*)>(
        thunk_SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks)(secondaryNode);

    this->DispatchTurnOrderActionSlotB0(3, 0x2508, 1);
    this->DispatchTurnOrderActionSlotB0(0, CityOrderActiveZoneIndex(), 1);
  }

  // Civil work order (serializedStatusFlags[2] < '3').
  if (this->serializedStatusFlags[2] < 0x33) {
    bool needsCivOrder = false;
    void** minorNationEntry = g_apMinorNationCapabilityObjects;
    short zoneCursor = 7;
    do {
      if (*reinterpret_cast<short*>(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) +
                                    (zoneCursor + nationSlot * 0x17) * 2 + 0x79c) > 0xa9) {
        void* entry = *minorNationEntry;
        short matchTag;
        if (entry != 0 &&
            (matchTag = *reinterpret_cast<short*>(reinterpret_cast<char*>(entry) + 0xe)) > 99 &&
            matchTag < 200) {
          if (matchTag < 200) {
            if (matchTag < 100) {
              matchTag = *reinterpret_cast<short*>(reinterpret_cast<char*>(entry) + 0xc);
            } else {
              matchTag = matchTag - 100;
            }
          } else {
            matchTag = matchTag - 200;
          }
          if (matchTag == nationSlot) {
            goto nextEntry;
          }
        }
        needsCivOrder = true;
      }
    nextEntry:
      ++minorNationEntry;
      ++zoneCursor;
    } while (minorNationEntry <= &g_apMinorNationCapabilityObjects[15]);

    if (needsCivOrder) {
      TCivWorkOrderState* civOrder = new TCivWorkOrderState();
      int spawnTile = reinterpret_cast<int(__fastcall*)(void*, int, int, int)>(
          thunk_FindReachableRecruitSpawnTileWithVisitedReset)(
          g_pGlobalMapState, this->ownerNationSlot, 0, nationSlot);
      civOrder->thunk_InitializeCivWorkOrderState(7, spawnTile, nationSlot);
      this->SetNationPendingActionStateAndPayload(2, -1);
    }
  }

  // Final pending-action flush (serializedStatusFlags[0x0a] == '2').
  if (this->serializedStatusFlags[0x0a] == 0x32) {
    relationManager->navySecondaryCount68 += 2;
    this->DispatchTurnOrderActionSlotB0(1, 6, 2);
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}
#pragma optimize("", on)
