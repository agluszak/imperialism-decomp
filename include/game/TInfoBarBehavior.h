#pragma once

#include "game/TBehavior.h"
#include "game/mfc.h"

// TODO(manifest): describe TInfoBarBehavior and its role. Base edge (TBehavior) recovered from RTTI CRuntimeClass chain: TInfoBarBehavior -> TBehavior -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064eb10
class TInfoBarBehavior : public TBehavior {
public:
// === BEGIN GENERATED DECLS (TInfoBarBehavior) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4b0d10
  virtual ~TInfoBarBehavior(); // slot 0x01 (scalar deleting destructor)
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
  // slot 0x0d OrphanRetStub_004872e0 inherited unchanged (0x4872e0)
  virtual undefined InitializeInfoBarTagEntryWithOptionalDummyChild(int param_1, int * param_2) override; // slot 0x0e 0x4b0e20
  virtual undefined RefreshInfoBarCursorPanelRegionClip() override; // slot 0x0f 0x4b0f50
// === END GENERATED DECLS (TInfoBarBehavior) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TInfoBarBehavior 0xCTOR`).

  TInfoBarBehavior();
};

// === BEGIN GENERATED (TInfoBarBehavior) — refreshed by `just gen-class TInfoBarBehavior`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064eb10 (16 slots), object size 0x24, base TBehavior
//   slot 0x00  byte 0x00  0x004b0d10  override  GetTBehaviorClassNamePointer
//   slot 0x01  byte 0x04  0x004b0da0  override  VTableSlot01
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
//   slot 0x0d  byte 0x34  0x004872e0  inherited OrphanRetStub_004872e0
//   slot 0x0e  byte 0x38  0x004b0e20  override  InitializeInfoBarTagEntryWithOptionalDummyChild
//   slot 0x0f  byte 0x3c  0x004b0f50  override  RefreshInfoBarCursorPanelRegionClip
// object size 0x24 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TInfoBarBehavior) ===
