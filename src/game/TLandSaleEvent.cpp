#include "game/TLandSaleEvent.h"
#include "game/ui_tags_common.h"

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
  eventTag04 = kControlTagLand; // 'land'
}

// FUNCTION: IMPERIALISM 0x004e6740
undefined TLandSaleEvent::ApplyJoinEmpireMode2FinalizeNationNameState() {
  return 0;
}
