#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00653d90
class TTurnStartEvent : public TObject {
public:
  // === BEGIN GENERATED DECLS (TTurnStartEvent) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTurnStartEvent)
  virtual ~TTurnStartEvent() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined ApplyJoinEmpireMode2FinalizeNationNameState(); // slot 0x0a 0x4e6610
  // === END GENERATED DECLS (TTurnStartEvent) ===

  // Event-kind four-cc. Every construction site (TTurnStartEvent::CreateObject 0x4e65e0,
  // TLandSaleEvent::CreateObject 0x4e66c0, the network receive path 0x54a169) stamps the
  // 'erra' placeholder here before a concrete I<Event> initializer overwrites it with the
  // real kind (e.g. TLandSaleEvent::ILandSaleEvent stores 'land').
  int eventTag04; // +0x04

  // Fully inlined at every site (only the 'erra' store + the final vtable store survive
  // dead-store elimination of the intermediate vptr) -- defined in-class so the recompile
  // inlines it the same way; there is no out-of-line copy in the original.
  TTurnStartEvent() {
    eventTag04 = 0x65727261; // 'erra'
  }
};

ASSERT_SIZE(TTurnStartEvent, 0x8);
