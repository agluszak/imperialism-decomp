#include "game/TObject.h"

#include <string.h>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

IMPLEMENT_SERIAL(TObject, CObject, 1)

TObject::TObject() {}

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
