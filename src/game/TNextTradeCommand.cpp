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
// SYNTHETIC: IMPERIALISM 0x005ba370
// TNextTradeCommand::CreateObject

IMPLEMENT_DYNCREATE(TNextTradeCommand, TCommand)

// FUNCTION: IMPERIALISM 0x005ba4b0
void TNextTradeCommand::OrphanRetStub_00487a00() {}
