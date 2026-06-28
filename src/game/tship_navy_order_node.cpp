#include "game/TShip.h"

#include "game/TAdmiral.h"
#include "game/TZone.h"
#include "game/GameAssert.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/CString.h"

extern "C" TShip* g_pNavyPrimaryOrderListHead;
extern "C" short g_Task_Force_Order_LookupTable_00698110[];

void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);

static int* NavyZoneOrderDescriptorEnabledFlagPtr(short zoneIndex) {
  return reinterpret_cast<int*>(reinterpret_cast<char*>(g_Task_Force_Order_LookupTable_00698110) +
                                static_cast<int>(zoneIndex) * 0x24 + 0x10);
}

static short* NavyZoneOrderDescriptorStockCapPtr(short zoneIndex) {
  return reinterpret_cast<short*>(reinterpret_cast<char*>(g_Task_Force_Order_LookupTable_00698110) +
                                  static_cast<int>(zoneIndex) * 0x24 + 4);
}

// FUNCTION: IMPERIALISM 0x0054f8e0
TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short zoneIndex, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride) {
  if (*NavyZoneOrderDescriptorEnabledFlagPtr(zoneIndex) < 0) {
    return 0;
  }

  TShip* shipNode = new TShip();

  if (shipNode == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag();
    return 0;
  }

  shipNode->field08 = portZoneContext;
  shipNode->resourceType04 = zoneIndex;
  shipNode->ownerNationSlot14 = static_cast<short>(nationSlot);

  if (displayNameOverride == 0) {
    TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[zoneIndex]), &shipNode->displayName18);
    for (TShip* existing = g_pNavyPrimaryOrderListHead; existing != 0;
         existing = existing->nextOlder24) {
      if (existing != shipNode &&
          CompareAnsiStringsWithMbcsAwareness(
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(existing->displayName18)),
              reinterpret_cast<unsigned char*>(
                  (char*)static_cast<LPCSTR>(shipNode->displayName18))) == 0) {
        RegenerateNavyPrimaryOrderDisplayNameUntilUnique(shipNode);
        break;
      }
    }
  } else {
    CString temp(displayNameOverride);
    shipNode->displayName18 = temp;
  }

  shipNode->stockLevel1c = *NavyZoneOrderDescriptorStockCapPtr(zoneIndex);

  if (portZoneContext != 0) {
    portZoneContext->HandleKeyDown(nationSlot);
  }

  return shipNode;
}
