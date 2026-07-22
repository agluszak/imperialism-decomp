#include "game/TObject.h"

#include <string.h>

// SYNTHETIC: IMPERIALISM 0x00485e20
// TObject::GetRuntimeClass

// SYNTHETIC: IMPERIALISM 0x00485df0
// TObject::CreateObject

IMPLEMENT_SERIAL(TObject, CObject, 1)

IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY
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
IMPERIALISM_END_RETAIL_POLYMORPHIC_BYTE_COPY

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

// FUNCTION: IMPERIALISM 0x00485f70
void TObject::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00485f90
void TObject::ReadFrom(TStream* stream) {
  (void)stream;
}
