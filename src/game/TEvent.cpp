#include "game/TEvent.h"

extern "C" CRuntimeClass classRuntimeClass = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass* TEvent::GetRuntimeClass() const {
  return &classRuntimeClass;
}

// SYNTHETIC: IMPERIALISM 0x00492c70
// TEvent::`scalar deleting destructor'

