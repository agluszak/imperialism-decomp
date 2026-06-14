#include "game/TTransportPicture.h"
#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663160
CRuntimeClass g_pClassDescTTransportPicture = {nullptr, 0, 0, nullptr, nullptr};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00591d90
TTransportPicture* __cdecl CreateTTransportPictureInstance(void) {
  return new TTransportPicture();
}

// FUNCTION: IMPERIALISM 0x00591e50
CRuntimeClass* TTransportPicture::GetRuntimeClass() {
  return &g_pClassDescTTransportPicture;
}

// FUNCTION: IMPERIALISM 0x00591e70
TTransportPicture::TTransportPicture()
    : TPictureResourceEntryBase(), gaugeMetricId90(0x3a), splitValue94(0), splitValue96(0),
      splitLimit98((short)0xffff) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00591ec0
// TTransportPicture::`scalar deleting destructor'

TTransportPicture::~TTransportPicture() {}
