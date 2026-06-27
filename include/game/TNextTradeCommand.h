#pragma once

#include "game/TCommand.h"
#include <stddef.h>


// The 'NeXT' (0x4E655854) turn-event command enqueued onto the UI root
// controller. Real inheritance from TCommand: the base constructor installs the
// 0x648e28 vtable, then this class's constructor installs 0x0066da90 — reproducing
// the original two-stage vptr write without any manual vtable store. It overrides
// only slots 0, 1 and 11 (0x2c); slots 2-10 are inherited from TCommand.
// VTABLE: IMPERIALISM 0x0066da90
class TNextTradeCommand : public TCommand {
public:
// === BEGIN GENERATED DECLS (TNextTradeCommand) — refreshed by recover-class; do not hand-edit ===
  // slot 0x00 cmd_slot0 — declared in hand section (0x5ba3e0)
  // slot 0x01 ~TNextTradeCommand / cmd_slot1 — declared in hand section
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4878e0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94 inherited unchanged (0x487900)
  // slot 0x0b cmd_slot11 — declared in hand section (0x5ba4b0)
// === END GENERATED DECLS (TNextTradeCommand) ===
  TNextTradeCommand();

  DECLARE_DYNCREATE(TNextTradeCommand)
  undefined OrphanRetStub_00487a00() override;     // slot 0x0b 0x5ba4b0
  // slot 0x01 (dtor) overridden by ~TNextTradeCommand below (0x5ba430)

  virtual ~TNextTradeCommand();
};

ASSERT_SIZE(TNextTradeCommand, 0x18);

// === BEGIN GENERATED (TNextTradeCommand) — refreshed by `just gen-class TNextTradeCommand`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066da90 (12 slots), object size 0x18, base TCommand
//   slot 0x00  byte 0x00  0x005ba3e0  override  GetTEventClassNamePointer
//   slot 0x01  byte 0x04  0x005ba430  override  OrphanCallChain_C1_I17_00487470
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00485f70  inherited OrphanRetStub_0059ad90
//   slot 0x06  byte 0x18  0x00485f90  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x07  byte 0x1c  0x004878e0  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x00487900  inherited NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94
//   slot 0x0b  byte 0x2c  0x005ba4b0  override  OrphanRetStub_00487a00
// object size 0x18 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNextTradeCommand) ===
