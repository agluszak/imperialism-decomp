#include "game/stream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 thunk_DestructTObjectAndMaybeFree(void);

// Shared CObject runtime-class vtable (defined in TCapacityOrder.cpp).
extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

extern "C" {
char g_vtblTFileStream = 0;
char g_pClassDescTFileStream = 0;
char g_vtblTCountingStream = 0;
char g_pClassDescTCountingStream = 0;
char g_vtblTHandleStream = 0;
char g_pClassDescTHandleStream = 0;
}

// ---- TFileStream ----------------------------------------------------------

// FUNCTION: IMPERIALISM 0x004890F0
void* TFileStream::GetTFileStreamClassNamePointer() {
  return &g_pClassDescTFileStream;
}

// FUNCTION: IMPERIALISM 0x00489110
TFileStream* TFileStream::ConstructTFileStreamBaseState() {
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTFileStream);
  this->field04 = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00489130
void* TFileStream::DestructTFileStreamAndMaybeFree(byte freeSelfFlag) {
  reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructTObjectAndMaybeFree)(this);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// ---- TCountingStream ------------------------------------------------------

// FUNCTION: IMPERIALISM 0x004893F0
void* TCountingStream::GetTCountingStreamClassNamePointer() {
  return &g_pClassDescTCountingStream;
}

// FUNCTION: IMPERIALISM 0x00489410
TCountingStream* TCountingStream::ConstructTCountingStreamBaseState() {
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTCountingStream);
  this->field04 = 0;
  this->field08 = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00489470
void TCountingStream::DestructTCountingStreamBaseState() {
  *reinterpret_cast<void**>(this) =
      reinterpret_cast<void*>(&PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4);
}

// FUNCTION: IMPERIALISM 0x00489440
void* TCountingStream::DestructTCountingStreamAndMaybeFree(byte freeSelfFlag) {
  this->DestructTCountingStreamBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// ---- THandleStream --------------------------------------------------------

// FUNCTION: IMPERIALISM 0x004895C0
void* THandleStream::GetTHandleStreamClassNamePointer() {
  return &g_pClassDescTHandleStream;
}

// FUNCTION: IMPERIALISM 0x004895E0
THandleStream* THandleStream::ConstructTHandleStreamBaseState() {
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTHandleStream);
  this->field10 = 1;
  this->field04 = 0;
  this->field08 = 0;
  this->field14 = 0;
  this->field0c = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00489640
void THandleStream::DestructTHandleStreamBaseState() {
  *reinterpret_cast<void**>(this) =
      reinterpret_cast<void*>(&PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4);
}

// FUNCTION: IMPERIALISM 0x00489610
void* THandleStream::DestructTHandleStreamAndMaybeFree(byte freeSelfFlag) {
  this->DestructTHandleStreamBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}
