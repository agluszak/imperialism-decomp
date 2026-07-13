#include "game/TCommandHandler.h"
#include "game/TCommand.h"

TCommandHandler::TCommandHandler() : TEventHandler() {}

// SYNTHETIC: IMPERIALISM 0x004865e0
// TCommandHandler::`scalar deleting destructor'
TCommandHandler::~TCommandHandler() {}
// SYNTHETIC: IMPERIALISM 0x00486570
// TCommandHandler::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486630
// TCommandHandler::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCommandHandler, TEventHandler)

// FUNCTION: IMPERIALISM 0x00486650
void TCommandHandler::ConstructTCommandHandlerBaseState(TCommand* command) {
  command->DoIt();
  command->Free();
}
