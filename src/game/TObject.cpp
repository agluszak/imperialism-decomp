#include "game/TObject.h"

#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00694eb8
CRuntimeClass PTR_s_TObject_00694eb8 = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00485e20
CRuntimeClass* TObject::GetRuntimeClass() const {
  return &PTR_s_TObject_00694eb8;
}

// SYNTHETIC: IMPERIALISM 0x00485f50
// TObject::`scalar deleting destructor'
