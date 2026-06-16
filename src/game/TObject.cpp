#include "game/TObject.h"

#include "game/ArchiveStreamAdapter.h"
#include "game/TFileStream.h"

#include <string.h>

extern "C" {
// GLOBAL: IMPERIALISM 0x00694eb8
CRuntimeClass PTR_s_TObject_00694eb8 = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00415ce0
TObject* TObject::ShallowFree() {
  CRuntimeClass* runtimeClass = GetRuntimeClass();
  unsigned int payloadSize = static_cast<unsigned int>(runtimeClass->m_nObjectSize);
  GetRuntimeClass();
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

// SYNTHETIC: IMPERIALISM 0x00485f50
// TObject::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00485e90
void TObject::Serialize(CArchive& archive) {
  ArchiveStreamAdapter* adapter = new ArchiveStreamAdapter(&archive);
  TFileStream stream;
  stream.SetBackingArchive(adapter);

  if (archive.IsLoading()) {
    ReadFrom(&stream);
  } else {
    WriteTo(&stream);
  }

  adapter->Free();
}

// FUNCTION: IMPERIALISM 0x00485f70
void TObject::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00485f90
void TObject::ReadFrom(TStream* stream) {
  (void)stream;
}
