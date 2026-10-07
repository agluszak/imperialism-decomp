#include "game/app/TObject.h"

#include "game/ArchiveStreamAdapter.h"
#include "game/core/TFileStream.h"

#include <string.h>

IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY
// FUNCTION: IMPERIALISM 0x00415ce0
TObject* TObject::ShallowFree() {
  CRuntimeClass* runtimeClass = GetRuntimeClass();
  unsigned int payloadSize = runtimeClass->m_nObjectSize;
  runtimeClass = GetRuntimeClass();
  CObject* destObject = runtimeClass->CreateObject();
  if (destObject == 0) {
    return 0;
  }
  memcpy(destObject, this, payloadSize);
  return static_cast<TObject*>(destObject);
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

IMPLEMENT_SERIAL(TObject, CObject, 1)

// FUNCTION: IMPERIALISM 0x00485e90
void TObject::Serialize(CArchive& archive) {
  ArchiveStreamAdapter adapter(&archive);
  TFileStream stream;
  stream.IFileStream(&adapter);

  if (archive.IsStoring()) {
    WriteTo(&stream);
  } else {
    ReadFrom(&stream);
  }
}

// FUNCTION: IMPERIALISM 0x00485f70
void TObject::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x00485f90
void TObject::ReadFrom(TStream* stream) {}
