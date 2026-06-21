#include "game/TNextTradeCommand.h"

// The base TCommand constructor installs vtable 0x648e28; this constructor then
// installs 0x654e50 (compiler-emitted from the // VTABLE: annotation). No manual
// vptr store. The original construction is inlined at the `new TNextTradeCommand()`
// call site, so this constructor has no standalone FUNCTION address.
// Overridden vtable slots (placeholders, like the TCommand base bodies).

TNextTradeCommand::TNextTradeCommand() : TCommand() {}

// SYNTHETIC: IMPERIALISM 0x005ba430
// TNextTradeCommand::`scalar deleting destructor'
TNextTradeCommand::~TNextTradeCommand() {}

// FUNCTION: IMPERIALISM 0x005ba3e0
void TNextTradeCommand::cmd_slot0() {}

// slot 0x01 shares scalar dtor address — cmd_slot1 is a separate curated name for the
// deleting-dtor slot in the original; provide an empty body only when not the dtor.
void TNextTradeCommand::cmd_slot1() {}

// FUNCTION: IMPERIALISM 0x005ba4b0
void TNextTradeCommand::cmd_slot11() {}
