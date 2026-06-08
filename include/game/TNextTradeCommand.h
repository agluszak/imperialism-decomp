#pragma once

#include "game/TCommand.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x00654e50
// The 'NeXT' (0x4E655854) turn-event command enqueued onto the UI root
// controller. Real inheritance from TCommand: the base constructor installs the
// 0x648e28 vtable, then this class's constructor installs 0x654e50 — reproducing
// the original two-stage vptr write without any manual vtable store. It overrides
// only slots 0, 1 and 11 (0x2c); slots 2-10 are inherited from TCommand.
class TNextTradeCommand : public TCommand {
public:
  TNextTradeCommand();

  void cmd_slot0();  // override 0 (0x00)
  void cmd_slot1();  // override 1 (0x04)
  void cmd_slot11(); // override 11 (0x2c)

  void* operator new(size_t size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void*) {}
};

ASSERT_SIZE(TNextTradeCommand, 0x18);
