#pragma once

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653d90
class TTurnStartEvent : public TObject {
public:
  DECLARE_DYNCREATE(TTurnStartEvent)
  virtual ~TTurnStartEvent() override; // slot 0x01 (scalar deleting destructor)
  virtual void ApplyJoinEmpireMode2FinalizeNationNameState(); // slot 0x0a 0x4e6610

  // Event-kind four-cc. Every construction site (TTurnStartEvent::CreateObject 0x4e65e0,
  // TLandSaleEvent::CreateObject 0x4e66c0, the network receive path 0x54a169) stamps the
  // 'erra' placeholder here before a concrete I<Event> initializer overwrites it with the
  // real kind (e.g. TLandSaleEvent::ILandSaleEvent stores 'land').
  int eventTag04; // +0x04

  // Fully inlined at every site (only the 'erra' store + the final vtable store survive
  // dead-store elimination of the intermediate vptr) -- defined in-class so the recompile
  // inlines it the same way; there is no out-of-line copy in the original.
  TTurnStartEvent() {
    eventTag04 = kControlTagErra; // 'erra'
  }
};

ASSERT_SIZE(TTurnStartEvent, 0x8);
