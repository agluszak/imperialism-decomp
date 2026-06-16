#include "game/TObject.h"

#include <string.h>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
// GLOBAL: IMPERIALISM 0x00694eb8
CRuntimeClass PTR_s_TObject_00694eb8 = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00415ce0
TObject* TObject::ShallowFree() {
  CRuntimeClass* runtimeClass = GetRuntimeClass();
  unsigned int payloadSize = static_cast<unsigned int>(runtimeClass->m_nObjectSize);
  runtimeClass = GetRuntimeClass();
  CObject* destObject = runtimeClass->CreateObject();
  if (destObject == 0) {
    return 0;
  }
  memcpy(destObject, this, payloadSize);
  return reinterpret_cast<TObject*>(destObject);
}

// FUNCTION: IMPERIALISM 0x004798b0
void TObject::Free() {
  if (this == 0) {
    return;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004798d0
TObject* TObject::ShallowClone() {
  return ShallowFree();
}

// FUNCTION: IMPERIALISM 0x00485e20
CRuntimeClass* TObject::GetRuntimeClass() const {
  return &PTR_s_TObject_00694eb8;
}

// SYNTHETIC: IMPERIALISM 0x00484990
// TObject::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00485f50
void TObject::RestoreConstructionSentinelVtable() {
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(0x0066fec4);
}

// FUNCTION: IMPERIALISM 0x00485f70
void TObject::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00485f90
void TObject::ReadFrom(TStream* stream) {
  (void)stream;
}
