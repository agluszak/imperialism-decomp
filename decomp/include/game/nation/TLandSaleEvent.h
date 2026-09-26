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

  short tileIndex08;  // +0x08 — first ILandSaleEvent argument
  short nationCode0a; // +0x0a — second ILandSaleEvent argument

  // Second-phase initializer (Mac oracle: TLandSaleEvent::ILandSaleEvent(short, short)).
  // Stores the payload pair and restamps the event tag from 'erra' to 'land'. 0x004e6710.
  void ILandSaleEvent(short tileIndex, short nationCode);
};

ASSERT_SIZE(TLandSaleEvent, 0xc);
