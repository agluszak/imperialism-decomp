#include "game/TEvent.h"

IMPLEMENT_DYNCREATE(TEvent, TObject)

TEvent::TEvent() : commandNumber(0), dispatchMessage(0), sourceHandler(0), targetHandler(0) {}

// SYNTHETIC: IMPERIALISM 0x00492c70
// TEvent::`scalar deleting destructor'
TEvent::~TEvent() {}
