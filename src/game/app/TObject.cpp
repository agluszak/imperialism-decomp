#include "game/app/TObject.h"

#include "game/ArchiveStreamAdapter.h"
#include "game/core/TFileStream.h"

#include <string.h>

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

// SYNTHETIC: IMPERIALISM 0x00484990
// TObject::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x00485df0
// TObject::CreateObject

IMPLEMENT_SERIAL(TObject, CObject, 1)

// SYNTHETIC: IMPERIALISM 0x00485e20
// TObject::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x00485e90
void TObject::Serialize(CArchive& archive) {
  ArchiveStreamAdapter adapter(&archive);
  TFileStream stream;
  stream.SetBackingArchive(&adapter);

  // Storing is the fall-through and loading the jump target (0x485ef1 JZ -> 0x485f09),
  // so the test has to be written the way the original asks it: IsStoring compiles to
  // the NOT ECX / TEST CL,1 pair at 0x485ee5, which the IsLoading spelling inverts.
  if (archive.IsStoring()) {
    WriteTo(&stream);
  } else {
    ReadFrom(&stream);
  }
}

// FUNCTION: IMPERIALISM 0x00485f70
void TObject::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00485f90
void TObject::ReadFrom(TStream* stream) {
  (void)stream;
}
