#include "game/ui_core/TCommandHandler.h"
#include "game/ui_core/TCommand.h"

IMPLEMENT_DYNCREATE(TCommandHandler, TEventHandler)

// FUNCTION: IMPERIALISM 0x00486650
void TCommandHandler::PerformCommand(TCommand* command) {
  command->DoIt();
  command->Free();
}
