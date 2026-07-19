#include "game/TTacticalAdiosPicture.h"

#include "game/TControl.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x0045d430
// TTacticalAdiosPicture::`scalar deleting destructor'
TTacticalAdiosPicture::~TTacticalAdiosPicture() {}
// SYNTHETIC: IMPERIALISM 0x005ad430
// TTacticalAdiosPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad4b0
// TTacticalAdiosPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalAdiosPicture, TPicture)

TTacticalAdiosPicture::TTacticalAdiosPicture() {}

// FUNCTION: IMPERIALISM 0x005ad4d0
void TTacticalAdiosPicture::NoOpUiLifecycleHook(int arg) {
}

// FUNCTION: IMPERIALISM 0x005ad650
void TTacticalAdiosPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagOkay) {
    static_cast<TControl*>(OwnerPanel())
        ->SetTextStyleAndMaybeRefresh(
            reinterpret_cast<const TUiTextStyleDescriptor*>(sourceHandler->controlTag), 1);
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
