#pragma once

#include "game/TTurnStartEvent.h"
#include "game/mfc.h"

// TODO(manifest): describe TLandSaleEvent and its role. Base edge (TTurnStartEvent) recovered from RTTI CRuntimeClass chain: TLandSaleEvent -> TTurnStartEvent -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00653290
class TLandSaleEvent : public TTurnStartEvent {
public:
// === BEGIN GENERATED DECLS (TLandSaleEvent) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TLandSaleEvent)
  virtual ~TLandSaleEvent(); // slot 0x01 (scalar deleting destructor)
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

// === BEGIN GENERATED (TLandSaleEvent) — refreshed by `just gen-class TLandSaleEvent`; do not hand-edit ===
// clang-format off
// vtable @ 0x00653290 (11 slots), object size 0x0c, base TTurnStartEvent
//   slot 0x00  byte 0x00  0x004e66f0  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x01  byte 0x04  0x004d49a0  override  ApplyJoinEmpireModeForTargetNation
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004e6740  override  ApplyJoinEmpireMode2FinalizeNationNameState
// object size 0x0c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TLandSaleEvent) ===
