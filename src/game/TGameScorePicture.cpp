#include "game/TGameScorePicture.h"

#include "game/TControl.h"
#include "game/TSimMgr.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0045afb0
// TGameScorePicture::`scalar deleting destructor'
TGameScorePicture::~TGameScorePicture() {}
// SYNTHETIC: IMPERIALISM 0x0057b000
// TGameScorePicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0057b080
// TGameScorePicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameScorePicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0045af80
TGameScorePicture::TGameScorePicture() {}

// FUNCTION: IMPERIALISM 0x0057b0a0
void TGameScorePicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x0057b620
void TGameScorePicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::HandleEvent(commandId, sourceHandler, event);
  if (commandId == 0xa && sourceHandler->controlTag == kTagDone) {
    ReinitializeGameFlowAndPostTurnEventCode(0x5e0);
  }
}
