#include "game/TTransportPicture.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x663160
char g_pClassDescTTransportPicture;

} // namespace

// FUNCTION: IMPERIALISM 0x00591d90
TTransportPicture* __cdecl CreateTTransportPictureInstance(void) {
  return new TTransportPicture();
}

// FUNCTION: IMPERIALISM 0x00591e50
void* __cdecl GetTTransportPictureClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTransportPicture);
}

// FUNCTION: IMPERIALISM 0x00591e70
TTransportPicture::TTransportPicture()
    : TPictureResourceEntryBase(), gaugeMetricId90(0x3a), splitValue94(0), splitValue96(0),
      splitLimit98((short)0xffff) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00591ec0
// TTransportPicture::`scalar deleting destructor'
