#pragma once

#include "compat.h"
#include "decomp_types.h"

// TObject-family command base (its MFC RTTI classdesc follows the vtable in
// .rdata). Modeled as a standalone polymorphic class because its constructor
// (0x00487820) is self-contained: it installs the 0x648e28 vtable and zeroes its
// five payload fields without chaining to a base constructor. The twelve virtual
// slots model the native vtable shape (0x00-0x2c); slots 2-10 are shared with the
// TNextTradeCommand override, which only replaces slots 0/1/11. Bodies are
// vtable-shape placeholders.
// VTABLE: IMPERIALISM 0x00648e28
class TCommand {
public:
// === BEGIN GENERATED DECLS (TCommand) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x487800
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4878e0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94(); // slot 0x0a 0x487900
  virtual undefined OrphanRetStub_00487a00(); // slot 0x0b 0x487a00
// === END GENERATED DECLS (TCommand) ===
  int field04; // 0x04
  int field08; // 0x08
  int field0c; // 0x0c
  int field10; // 0x10
  int field14; // 0x14

  TCommand();

  virtual void cmd_slot0();  // 0 (0x00)
  virtual void cmd_slot1();  // 1 (0x04)
  virtual void cmd_slot2();  // 2 (0x08)
  virtual void cmd_slot3();  // 3 (0x0c)
  virtual void cmd_slot4();  // 4 (0x10)
  virtual void cmd_slot5();  // 5 (0x14)
  virtual void cmd_slot6();  // 6 (0x18)
  virtual void cmd_slot7();  // 7 (0x1c)
  virtual void cmd_slot8();  // 8 (0x20)
  virtual void cmd_slot9();  // 9 (0x24)
  virtual void cmd_slot10(); // 10 (0x28)
  virtual void cmd_slot11(); // 11 (0x2c)

  // 0x004878a0: seeds the range/cursor payload (resolving a default when the
  // second argument is zero). Only the first two arguments are used; the native
  // signature is a five-argument thiscall (RET 0x14).
  void InitializeRangePair(int arg1, int arg2, int arg3, int arg4, int arg5);

protected:
  ~TCommand() {}
};

ASSERT_SIZE(TCommand, 0x18);

// === BEGIN GENERATED (TCommand) — refreshed by `just gen-class TCommand`; do not hand-edit ===
// clang-format off
// vtable @ 0x00648e28 (12 slots), object size 0x18, base TEvent
//   slot 0x00  byte 0x00  0x00487800  override  GetTEventClassNamePointer
//   slot 0x01  byte 0x04  0x00487850  override  OrphanCallChain_C1_I17_00487470
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00485f70  inherited OrphanRetStub_0059ad90
//   slot 0x06  byte 0x18  0x00485f90  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x07  byte 0x1c  0x004878e0  override  QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x00487900  new       NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94
//   slot 0x0b  byte 0x2c  0x00487a00  new       OrphanRetStub_00487a00
// object size 0x18 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCommand) ===
