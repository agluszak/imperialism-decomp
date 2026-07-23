#include "game/ui_screens/TSpaceCommand.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"

// FUNCTION: IMPERIALISM 0x005751f0
void TSpaceCommand::DoIt() {
  setupPicture18->MajorTomToGroundControl(mode1c);
}

// SYNTHETIC: IMPERIALISM 0x00575210
// TSpaceCommand::`scalar deleting destructor'
TSpaceCommand::~TSpaceCommand() {}
// SYNTHETIC: IMPERIALISM 0x00575180
// TSpaceCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575260
// TSpaceCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSpaceCommand, TCommand)

TSpaceCommand::TSpaceCommand() {}
