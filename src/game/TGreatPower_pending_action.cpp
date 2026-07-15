#include "game/TGreatPower.h"
#include "game/TOcean.h"
#include "game/TGreatPower_internal.h"
#include "game/TMilitaryUnit.h"
#include "game/TCivUnit.h"
#include "game/TAdmiral.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TZone.h"
#include "game/TMinor.h"
#include "game/TShip.h"
#include "game/global_data_tables.h"
#include "game/TDiplomacyMgr.h"

#include "decomp_types.h"

// FUNCTION: IMPERIALISM 0x004d7770
void TCountry::CreateMilitaryRecruitOrderForNode(int nodeContext) {
  int capabilityBonus = 0;
  if (static_cast<unsigned short>(this->nationSlot) < 7) {
    const TTechMgr::MilitaryCapRow& capabilityRow =
        g_pCityOrderCapabilityState->militaryCapRows39d[this->nationSlot];
    if (capabilityRow.eliteRecruitFlag != 0) {
      capabilityBonus = 0x10;
    } else {
      char capabilityFlag = static_cast<char>(capabilityRow.recruitTierFlag);
      capabilityBonus = (static_cast<int>(-capabilityFlag) >> 0x1f) & 8;
    }
  }
  TMilitaryUnit* militaryOrder = new TMilitaryUnit();
  militaryOrder->InitializeRecruitOrderState(static_cast<short>(capabilityBonus), nodeContext,
                                             this->nationSlot);
  militaryOrder->SetOrderModeSlot34(2, -1);
}

// FUNCTION: IMPERIALISM 0x004dab20
void TGreatPower::ExecuteNationPendingActionStateMachine(void) {
  TCity* cityPtr = this->city;
  cityPtr->ProduceUnits();

  short nationSlot = this->nationSlot;

  // Land recruit order (serializedStatusFlags[1] == '2').
  if (this->serializedStatusFlags[1] == 0x32) {
    TMilitaryUnit* militaryOrder = new TMilitaryUnit();
    int nodeContext = this->GetHomeRegionCityRecordIndex();
    short capValue = g_pCityOrderCapabilityState->nationCapRows1e8[nationSlot].slots[9];
    militaryOrder->InitializeRecruitOrderState(capValue, nodeContext, nationSlot);
    this->DispatchTurnOrderActionSlotB0(3, capValue, 1);
  }

  // Navy primary/secondary order (serializedStatusFlags[0] == '2').
  if (this->serializedStatusFlags[0] == 0x32) {
    short zoneIndex = g_pCityOrderCapabilityState->activeZoneIndex1d4;
    TZone* portZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationSlot);
    TShip* primaryOrder =
        CreateNavyPrimaryOrderNodeAndAssignDisplayName(zoneIndex, portZone, nationSlot, 0);

    ++cityPtr->orderCountByType5c[g_pCityOrderCapabilityState->activeZoneIndex1d4];

    TAdmiral* secondaryNode = new TAdmiral(nationSlot);
    secondaryNode->SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(primaryOrder);

    this->DispatchTurnOrderActionSlotB0(3, 0x2508, 1);
    this->DispatchTurnOrderActionSlotB0(0, g_pCityOrderCapabilityState->activeZoneIndex1d4, 1);
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
          if (ownerTag > 99 && ownerTag < 200 && static_cast<short>(ownerTag - 100) == nationSlot) {
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
      TCivUnit* civOrder = new TCivUnit();
      civOrder->InitializeCivWorkOrderState(
          7,
          g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(this->homeRegionIndex,
                                                                           0),
          nationSlot);
      this->SetNationPendingActionStateAndPayload(2, -1);
    }
  }

  // Final pending-action flush (serializedStatusFlags[0x0a] == '2').
  if (this->serializedStatusFlags[0x0a] == 0x32) {
    this->city->orderCountByType5c[6] += 2; // navy secondary-order counter
    this->DispatchTurnOrderActionSlotB0(1, 6, 2);
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}
