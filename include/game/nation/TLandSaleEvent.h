#pragma once

#include "game/nation/TTurnStartEvent.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653290
class TLandSaleEvent : public TTurnStartEvent {
public:
  DECLARE_DYNCREATE(TLandSaleEvent)
  virtual ~TLandSaleEvent() override; // slot 0x01 (scalar deleting destructor)
  virtual undefined ApplyJoinEmpireMode2FinalizeNationNameState() override; // slot 0x0a 0x4e6740

  short tileIndex08;  // +0x08 — first ILandSaleEvent argument
  short nationCode0a; // +0x0a — second ILandSaleEvent argument

  // Fully inlined at every construction site (0x4e66c0 CreateObject, 0x54a169 network
  // receive): only the base 'erra' tag store plus the final vtable store survive, so the
  // ctor is defined in-class; there is no out-of-line copy in the original.
  TLandSaleEvent() : TTurnStartEvent() {}

  // Second-phase initializer (Mac oracle: TLandSaleEvent::ILandSaleEvent(short, short)).
  // Stores the payload pair and restamps the event tag from 'erra' to 'land'. 0x004e6710.
  void ILandSaleEvent(short tileIndex, short nationCode);
};

ASSERT_SIZE(TLandSaleEvent, 0xc);
