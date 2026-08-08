#include "game/ui_core/TCommandHandler.h"
#include "game/ui_core/TCommand.h"
// SYNTHETIC: IMPERIALISM 0x004865e0
// TCommandHandler::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x00486570
// TCommandHandler::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486630
// TCommandHandler::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCommandHandler, TEventHandler)

// FUNCTION: IMPERIALISM 0x00486650
void TCommandHandler::PerformCommand(TCommand* command) {
  command->DoIt();
  command->Free();
}
