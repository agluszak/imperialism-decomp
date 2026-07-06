#pragma once

#include "game/TTurnStartEvent.h"
#include "game/mfc.h"

// TODO(manifest): describe TLandSaleEvent and its role. Base edge (TTurnStartEvent) recovered from RTTI CRuntimeClass chain: TLandSaleEvent -> TTurnStartEvent -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00653290
class TLandSaleEvent : public TTurnStartEvent {
public:
// === BEGIN GENERATED DECLS (TLandSaleEvent) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TLandSaleEvent)
  virtual ~TLandSaleEvent() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined ApplyJoinEmpireMode2FinalizeNationNameState() override; // slot 0x0a 0x4e6740
// === END GENERATED DECLS (TLandSaleEvent) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TLandSaleEvent 0xCTOR`).

  TLandSaleEvent();
};

