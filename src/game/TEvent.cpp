#include "game/TEvent.h"

// SYNTHETIC: IMPERIALISM 0x00489f00
// TEvent::CreateObject

// SYNTHETIC: IMPERIALISM 0x00489f40
// TEvent::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEvent, TObject)

TEvent::TEvent() : commandNumber(0), dispatchMessage(0), sourceHandler(0), targetHandler(0) {}

// SYNTHETIC: IMPERIALISM 0x00492c70
// TEvent::`scalar deleting destructor'
TEvent::~TEvent() {}
