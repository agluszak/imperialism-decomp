#pragma once

#include "game/nation/TTurnStartEvent.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653290
class TLandSaleEvent : public TTurnStartEvent {
public:
  DECLARE_DYNCREATE(TLandSaleEvent)
  // FUNCTION: IMPERIALISM 0x004d49d0
  virtual ~TLandSaleEvent() override {}
  virtual void Execute() override;

  short tileIndex;  // first ILandSaleEvent argument
  short nationCode; // second ILandSaleEvent argument

  void ILandSaleEvent(short tileIndex, short nationCode);
};

ASSERT_SIZE(TLandSaleEvent, 0xc);
