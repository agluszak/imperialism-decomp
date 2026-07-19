#include "game/TShip.h"
#include "game/navy_order.h"

#include "game/TAdmiral.h"
#include "game/TZone.h"
#include "game/GameAssert.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/CString.h"

extern "C" TShip* g_pNavyPrimaryOrderListHead;

void __fastcall RegenerateNavyPrimaryOrderDisplayNameUntilUnique(TShip* shipNode);

// FUNCTION: IMPERIALISM 0x0054f8e0
TShip* CreateNavyPrimaryOrderNodeAndAssignDisplayName(short resourceType, TZone* portZoneContext,
                                                      int nationSlot, char* displayNameOverride) {
  if (g_NavyOrderResourceDescriptorTable[resourceType].enabledFlagOrBucketOffset < 0) {
    return 0;
  }

  TShip* shipNode = new TShip();

  if (shipNode == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UNavy.cpp", 0x1fc);
    return 0;
  }

  shipNode->field08 = portZoneContext;
  shipNode->resourceType04 = resourceType;
  shipNode->ownerNationSlot14 = static_cast<short>(nationSlot);

  if (displayNameOverride == 0) {
    TAdmiral::GenerateMappedFlavorTextByNationSlotField0C(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[resourceType]),
        &shipNode->displayName18);
    for (TShip* existing = g_pNavyPrimaryOrderListHead; existing != 0;
         existing = existing->nextOlder24) {
      if (existing != shipNode &&
          _mbscmp(
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

  shipNode->stockLevel1c = g_NavyOrderResourceDescriptorTable[resourceType].stockCap;

  if (portZoneContext != 0) {
    portZoneContext->HandleKeyDown(nationSlot);
  }

  return shipNode;
}
