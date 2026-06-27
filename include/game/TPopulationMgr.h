#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TPopulationMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TPopulationMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f9b0
class TPopulationMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TPopulationMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TPopulationMgr)
  virtual ~TPopulationMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4b6850
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b68f0
  virtual void Free() override; // slot 0x07 0x4b6990
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins09_004b5d10(int param_1, int param_2); // slot 0x0a 0x4b5d10
  virtual undefined OrphanLeaf_NoCall_Ins47_004b5dc0(short param_1, short param_2, short param_3); // slot 0x0b 0x4b5dc0
  virtual undefined OrphanLeaf_NoCall_Ins20_004b5d50(short param_1); // slot 0x0c 0x4b5d50
  virtual undefined OrphanLeaf_NoCall_Ins87_004b66a0(short param_1, short param_2); // slot 0x0d 0x4b66a0
  virtual undefined Helper_Uses_thunk_DeleteObjectIfNonNullViaVslot04_At004b5ed0(); // slot 0x0e 0x4b5ed0
  virtual undefined OrphanLeaf_NoCall_Ins111_004b6260(short * param_1, ushort * param_2); // slot 0x0f 0x4b6260
  virtual undefined OrphanCallChain_C2_I61_004b65b0(); // slot 0x10 0x4b65b0
  virtual undefined OrphanCallChain_C2_I24_004b5e80(); // slot 0x11 0x4b5e80
  virtual undefined OrphanLeaf_NoCall_Ins50_004b63e0(); // slot 0x12 0x4b63e0
  virtual undefined OrphanLeaf_NoCall_Ins26_004b67e0(short param_1, short param_2); // slot 0x13 0x4b67e0
  virtual undefined OrphanLeaf_NoCall_Ins63_004b64c0(); // slot 0x14 0x4b64c0
// === END GENERATED DECLS (TPopulationMgr) ===

  void NotifyProductionPresetSlot2C(int a, int b, int c) {
    OrphanLeaf_NoCall_Ins47_004b5dc0(static_cast<short>(a), static_cast<short>(b),
                                        static_cast<short>(c));
  }
  short* GetSummaryArraySlot50();

  short stockLevel1c; // +0x1c — low-stock flag derivation in TCity slot 0x0b

  TPopulationMgr();
};

// === BEGIN GENERATED (TPopulationMgr) — refreshed by `just gen-class TPopulationMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f9b0 (21 slots), object size 0x50, base TObject
//   slot 0x00  byte 0x00  0x004b5b70  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004b5bb0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004b6850  override  WriteTo
//   slot 0x06  byte 0x18  0x004b68f0  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004b6990  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004b5d10  override  OrphanLeaf_NoCall_Ins09_004b5d10
//   slot 0x0b  byte 0x2c  0x004b5dc0  override  OrphanLeaf_NoCall_Ins47_004b5dc0
//   slot 0x0c  byte 0x30  0x004b5d50  override  OrphanLeaf_NoCall_Ins20_004b5d50
//   slot 0x0d  byte 0x34  0x004b66a0  override  OrphanLeaf_NoCall_Ins87_004b66a0
//   slot 0x0e  byte 0x38  0x004b5ed0  override  Helper_Uses_thunk_DeleteObjectIfNonNullViaVslot04_At004b5ed0
//   slot 0x0f  byte 0x3c  0x004b6260  override  OrphanLeaf_NoCall_Ins111_004b6260
//   slot 0x10  byte 0x40  0x004b65b0  override  OrphanCallChain_C2_I61_004b65b0
//   slot 0x11  byte 0x44  0x004b5e80  override  OrphanCallChain_C2_I24_004b5e80
//   slot 0x12  byte 0x48  0x004b63e0  override  OrphanLeaf_NoCall_Ins50_004b63e0
//   slot 0x13  byte 0x4c  0x004b67e0  override  OrphanLeaf_NoCall_Ins26_004b67e0
//   slot 0x14  byte 0x50  0x004b64c0  override  OrphanLeaf_NoCall_Ins63_004b64c0
// object size 0x50 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TPopulationMgr) ===
