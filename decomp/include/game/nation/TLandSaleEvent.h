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
  virtual ~TLandSaleEvent() override {} // slot 0x01 (scalar deleting destructor)
  virtual void Execute() override;      // slot 0x0a 0x4e6740

  short tileIndex;  // +0x08 — first ILandSaleEvent argument
  short nationCode; // +0x0a — second ILandSaleEvent argument

  void ILandSaleEvent(short tileIndex, short nationCode);
};

ASSERT_SIZE(TLandSaleEvent, 0xc);
