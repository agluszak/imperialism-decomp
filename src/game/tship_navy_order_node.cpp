#include "game/TShip.h"
#include "game/navy_order.h"

#include "game/TZone.h"
#include "game/GameAssert.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_invalidation_guard.h"
#include "game/CString.h"

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

  shipNode->location = portZoneContext;
  shipNode->type = resourceType;
  shipNode->nation = static_cast<short>(nationSlot);

  if (displayNameOverride == 0) {
    g_apTerrainTypeDescriptorTable[resourceType]->GenerateEthnicName(&shipNode->name);
    for (TShip* existing = g_pNavyPrimaryOrderListHead; existing != 0; existing = existing->next) {
      if (existing != shipNode &&
          _mbscmp(reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(existing->name)),
                  reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(shipNode->name))) ==
              0) {
        RegenerateNavyPrimaryOrderDisplayNameUntilUnique(shipNode);
        break;
      }
    }
  } else {
    CString temp(displayNameOverride);
    shipNode->name = temp;
  }

  shipNode->strength = g_NavyOrderResourceDescriptorTable[resourceType].stockCap;

  if (portZoneContext != 0) {
    portZoneContext->HandleKeyDown(nationSlot);
  }

  return shipNode;
}
