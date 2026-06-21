#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"

// VTABLE: IMPERIALISM 0x00648d60
class TBehavior : public TObject {
public:
// === BEGIN GENERATED DECLS (TBehavior) — refreshed by recover-class; do not hand-edit ===
  virtual ~TBehavior(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanTiny_SetDwordEcxOffset_8_00487280(); // slot 0x0a 0x487280
  virtual undefined OrphanLeaf_NoCall_Ins02_004872a0(); // slot 0x0b 0x4872a0
  virtual undefined CreateTDialogBehaviorInstance(); // slot 0x0c 0x4872c0
  virtual undefined OrphanRetStub_004872e0(); // slot 0x0d 0x4872e0
// === END GENERATED DECLS (TBehavior) ===
  TBehavior();

  CRuntimeClass* GetRuntimeClass() const override;
  virtual void SetDword08(undefined4 value);
  virtual unsigned char GetFlag0C();
  virtual void SetFlag0C(unsigned char value);
  virtual void NoOpSlot34(undefined4 value);

  undefined4 field_0x4;
  undefined4 field_0x8;
  unsigned char field_0xc;
  unsigned char padding_0xd[3];
};

ASSERT_SIZE(TBehavior, 0x10);

// === BEGIN GENERATED (TBehavior) — refreshed by `just gen-class TBehavior`; do not hand-edit ===
// clang-format off
// vtable @ 0x00648d60 (14 slots), object size 0x10, base TObject
//   slot 0x00  byte 0x00  0x004871c0  new       GetTBehaviorClassNamePointer
//   slot 0x01  byte 0x04  0x00487210  new       VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00485f70  new       OrphanRetStub_0059ad90
//   slot 0x06  byte 0x18  0x00485f90  new       OrphanCallChain_C11_I88_004874b0
//   slot 0x07  byte 0x1c  0x004798b0  new       QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x08  byte 0x20  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x00487280  new       OrphanTiny_SetDwordEcxOffset_8_00487280
//   slot 0x0b  byte 0x2c  0x004872a0  new       OrphanLeaf_NoCall_Ins02_004872a0
//   slot 0x0c  byte 0x30  0x004872c0  new       CreateTDialogBehaviorInstance
//   slot 0x0d  byte 0x34  0x004872e0  new       OrphanRetStub_004872e0
// object size 0x10 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TBehavior) ===
