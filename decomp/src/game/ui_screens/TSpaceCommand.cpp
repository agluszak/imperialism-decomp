#include "game/ui_screens/TSpaceCommand.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"

// FUNCTION: IMPERIALISM 0x005751f0
void TSpaceCommand::DoIt() {
  setupPicture18->MajorTomToGroundControl(mode1c);
}

// FUNCTION: IMPERIALISM 0x00575240
TSpaceCommand::~TSpaceCommand() {}

IMPLEMENT_DYNCREATE(TSpaceCommand, TCommand)
