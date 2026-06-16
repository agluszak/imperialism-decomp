#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/TMilitaryUnitOrderState.h"
#include "game/TCivWorkOrderState.h"
#include "game/TAdmiral.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TZone.h"
#include "game/TMinor.h"
#include "game/TShip.h"
#include "game/diplomacy_globals.h"
#include "game/TDiplomacyTurnStateManager.h"

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// FUNCTION: IMPERIALISM 0x004d7770
#pragma optimize("y", on)
void TCountry::CreateMilitaryRecruitOrderForNode(int nodeContext) {
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
  TCity* cityPtr = this->city;
  cityPtr->RefreshOrderStateSlot0C();

  short nationSlot = this->nationSlot;

  // Land recruit order (serializedStatusFlags[1] == '2').
  if (this->serializedStatusFlags[1] == 0x32) {
    TMilitaryUnitOrderState* militaryOrder = new TMilitaryUnitOrderState();
    int nodeContext = this->GetHomeRegionCityRecordIndex();
    short capValue = CityOrderCapForNation(nationSlot);
    militaryOrder->InitializeRecruitOrderState(capValue, nodeContext, nationSlot);
    this->DispatchTurnOrderActionSlotB0(3, capValue, 1);
  }

  // Navy primary/secondary order (serializedStatusFlags[0] == '2').
  if (this->serializedStatusFlags[0] == 0x32) {
    short zoneIndex = CityOrderActiveZoneIndex();
    TZone* portZone = TZone::FindFirstPortZoneContextByNation(nationSlot);
    TShip* primaryOrder =
        CreateNavyPrimaryOrderNodeAndAssignDisplayName(zoneIndex, portZone, nationSlot, 0);

    ++cityPtr->recruitZoneCount5c[CityOrderActiveZoneIndex()];

    TAdmiral* secondaryNode = new TAdmiral(nationSlot);
    secondaryNode->SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(primaryOrder);

    this->DispatchTurnOrderActionSlotB0(3, 0x2508, 1);
    this->DispatchTurnOrderActionSlotB0(0, CityOrderActiveZoneIndex(), 1);
  }

  // Civil work order (serializedStatusFlags[2] < '3').
  if (this->serializedStatusFlags[2] < 0x33) {
    bool needsCivOrder = false;
    TMinor** minorEntry = g_apMinorNationCapabilityObjects;
    short zoneCursor = 7;
    do {
      if (g_pDiplomacyTurnStateManager
              ->relationStandingScoreMatrix79c[zoneCursor + nationSlot * kNationSlotCount] > 0xa9) {
        TMinor* minor = *minorEntry;
        if (minor != 0) {
          short ownerTag = minor->encodedNationSlot;
          if (ownerTag > 99 && ownerTag < 200 &&
              ResolveMinorCapabilityOwnerNationSlot(minor) == nationSlot) {
            goto nextMinorEntry;
          }
        }
        needsCivOrder = true;
      }
    nextMinorEntry:
      ++minorEntry;
      ++zoneCursor;
    } while (minorEntry <= &g_apMinorNationCapabilityObjects[15]);

    if (needsCivOrder) {
      TCivWorkOrderState* civOrder = new TCivWorkOrderState();
      short spawnTile = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->ownerNationSlot, 0);
      civOrder->InitializeCivWorkOrderState(7, spawnTile, nationSlot);
      this->SetNationPendingActionStateAndPayload(2, -1);
    }
  }

  // Final pending-action flush (serializedStatusFlags[0x0a] == '2').
  if (this->serializedStatusFlags[0x0a] == 0x32) {
    cityPtr->navySecondaryCount68 += 2;
    this->DispatchTurnOrderActionSlotB0(1, 6, 2);
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}
#pragma optimize("", on)
