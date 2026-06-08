#include "game/TNextTradeCommand.h"

// The base TCommand constructor installs vtable 0x648e28; this constructor then
// installs 0x654e50 (compiler-emitted from the // VTABLE: annotation). No manual
// vptr store. The original construction is inlined at the `new TNextTradeCommand()`
// call site, so this constructor has no standalone FUNCTION address.
TNextTradeCommand::TNextTradeCommand() : TCommand() {}

// Overridden vtable slots (placeholders, like the TCommand base bodies).
void TNextTradeCommand::cmd_slot0() {}
void TNextTradeCommand::cmd_slot1() {}
void TNextTradeCommand::cmd_slot11() {}
