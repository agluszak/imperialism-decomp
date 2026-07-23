#include "game/nation/TLandSaleEvent.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"

// SYNTHETIC: IMPERIALISM 0x004d49a0
// TLandSaleEvent::`scalar deleting destructor'
TLandSaleEvent::~TLandSaleEvent() {}
// SYNTHETIC: IMPERIALISM 0x004e66c0
// TLandSaleEvent::CreateObject

// SYNTHETIC: IMPERIALISM 0x004e66f0
// TLandSaleEvent::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLandSaleEvent, TTurnStartEvent)

// FUNCTION: IMPERIALISM 0x004e6710
void TLandSaleEvent::ILandSaleEvent(short tileIndex, short nationCode) {
  tileIndex08 = tileIndex;
  nationCode0a = nationCode;
  eventTag04 = 0x6c616e64; // 'land'
}

// FUNCTION: IMPERIALISM 0x004e6740
void TLandSaleEvent::ApplyJoinEmpireMode2FinalizeNationNameState() {
  CString buyerName;
  CString sellerName;
  CString messageTemplate;
  CString message;

  short sellerNationTag = g_pGlobalMapState->terrainStateTable[tileIndex08].ownerNationTag04;
  TCountry* buyer = g_apTerrainTypeDescriptorTable[nationCode0a];
  if (buyer == 0) {
    buyerName = g_szEmptyString;
  } else {
    buyerName = g_pSimMgr->LoadNormalizedCredentialName(buyer->nationSlot);
  }
  TCountry* seller = g_apTerrainTypeDescriptorTable[sellerNationTag];
  if (seller == 0) {
    sellerName = g_szEmptyString;
  } else {
    sellerName = g_pSimMgr->LoadNormalizedCredentialName(seller->nationSlot);
  }

  if (g_pGlobalUiRootController->edgeScrollTarget48 != 0) {
    static_cast<TMapUberPicture*>(g_pGlobalUiRootController->edgeScrollTarget48)
        ->CenterOn(tileIndex08);
  }

  g_pSimMgr->GetString(0x274d, 6, &messageTemplate);
  scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(messageTemplate),
                         static_cast<LPCSTR>(sellerName), static_cast<LPCSTR>(buyerName));
  g_pUiRuntimeContext->ModalMessage(message, g_ptGreatPowerModalMessage, 0, 0);
}
