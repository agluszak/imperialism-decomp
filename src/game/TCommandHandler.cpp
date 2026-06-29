#include "game/TCommandHandler.h"
#include "game/TCommand.h"

TCommandHandler::TCommandHandler() : TEventHandler() {}

// SYNTHETIC: IMPERIALISM 0x004865e0
// TCommandHandler::`scalar deleting destructor'
TCommandHandler::~TCommandHandler() {}
IMPLEMENT_DYNCREATE(TCommandHandler, TEventHandler)

// FUNCTION: IMPERIALISM 0x00486650
void TCommandHandler::ConstructTCommandHandlerBaseState(TCommand* command) {
  command->OrphanRetStub_00487a00();
  command->Free();
}
