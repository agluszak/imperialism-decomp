#pragma once

#include "game/TBehavior.h"
#include "game/mfc.h"

// TODO(manifest): describe TDropShadowTextBehavior and its role. Base edge (TBehavior) recovered from RTTI CRuntimeClass chain: TDropShadowTextBehavior -> TBehavior -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064eb60
class TDropShadowTextBehavior : public TBehavior {
public:
// === BEGIN GENERATED DECLS (TDropShadowTextBehavior) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4b1080
  virtual ~TDropShadowTextBehavior(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a OrphanTiny_SetDwordEcxOffset_8_00487280 inherited unchanged (0x487280)
  // slot 0x0b OrphanLeaf_NoCall_Ins02_004872a0 inherited unchanged (0x4872a0)
  // slot 0x0c CreateTDialogBehaviorInstance inherited unchanged (0x4872c0)
  void NoOpSlot34(undefined4 value) override; // slot 0x0d byte 0x34 0x4b1150
// === END GENERATED DECLS (TDropShadowTextBehavior) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TDropShadowTextBehavior 0xCTOR`).

  TDropShadowTextBehavior();
};

// === BEGIN GENERATED (TDropShadowTextBehavior) — refreshed by `just gen-class TDropShadowTextBehavior`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064eb60 (14 slots), object size 0x14, base TBehavior
//   slot 0x00  byte 0x00  0x004b1080  override  GetTBehaviorClassNamePointer
//   slot 0x01  byte 0x04  0x004b10d0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x00487280  inherited OrphanTiny_SetDwordEcxOffset_8_00487280
//   slot 0x0b  byte 0x2c  0x004872a0  inherited OrphanLeaf_NoCall_Ins02_004872a0
//   slot 0x0c  byte 0x30  0x004872c0  inherited CreateTDialogBehaviorInstance
//   slot 0x0d  byte 0x34  0x004b1150  override  OrphanRetStub_004872e0
// object size 0x14 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TDropShadowTextBehavior) ===
