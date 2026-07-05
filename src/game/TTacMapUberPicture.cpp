#include "game/TTacMapUberPicture.h"

// FUNCTION: IMPERIALISM 0x0045d3b0
undefined TTacMapUberPicture::OrphanRetStub_0045d2a0(int param1) {
  // Real body forwards param1 to field94's own vtable slot 0x6b when field94 != 0 (ground
  // truth: `mov ecx,[this+0x94]; test ecx,ecx; jz ret; ... call [eax+0x1ac]`), but field94's
  // receiver class isn't recovered yet -- left as the pre-existing stub rather than fake the
  // dispatch (Hard Rule 12).
  (void)param1;
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0045d3e0
// TTacMapUberPicture::`scalar deleting destructor'
TTacMapUberPicture::~TTacMapUberPicture() {}
// SYNTHETIC: IMPERIALISM 0x005ad2e0
// TTacMapUberPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad380
// TTacMapUberPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacMapUberPicture, TMapUberUberPicture)

TTacMapUberPicture::TTacMapUberPicture() {}

// FUNCTION: IMPERIALISM 0x005ad3a0
void TTacMapUberPicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005ad3f0
void TTacMapUberPicture::ForwardParam(int param) {}
