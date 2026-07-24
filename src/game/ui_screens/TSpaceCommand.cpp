#include "game/ui_screens/TSpaceCommand.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"

// FUNCTION: IMPERIALISM 0x005751f0
void TSpaceCommand::DoIt() {
  setupPicture18->MajorTomToGroundControl(mode1c);
}

// SYNTHETIC: IMPERIALISM 0x00575210
// TSpaceCommand::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00575240
TSpaceCommand::~TSpaceCommand() {}
// SYNTHETIC: IMPERIALISM 0x00575180
// TSpaceCommand::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575260
// TSpaceCommand::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSpaceCommand, TCommand)

// NOOP: verified empty in original 0x005751b3 (no standalone TSpaceCommand::TSpaceCommand body exists: CreateObject 0x00575180 inlines this default ctor, calling the TCommand base ctor directly at that site)
TSpaceCommand::TSpaceCommand() {}
