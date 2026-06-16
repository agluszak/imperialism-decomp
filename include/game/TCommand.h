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
