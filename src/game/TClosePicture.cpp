#include "game/TAmtBar.h"
#include "game/TClosePicture.h"


undefined4 DispatchUiMouseEventToChildrenOrSelf(void);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

// GLOBAL: IMPERIALISM 0x662f38
extern "C" char g_pClassDescTClosePicture = 0;

} // namespace

// FUNCTION: IMPERIALISM 0x00586ad0
TClosePicture* __cdecl CreateTClosePictureInstance(void) {
  return new TClosePicture();
}

// FUNCTION: IMPERIALISM 0x00586b50
void* __cdecl GetTClosePictureClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTClosePicture);
}

void* TClosePicture::GetTEventHandlerClassNamePointer() {
  return GetTClosePictureClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x00586b70
TClosePicture::TClosePicture() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00586ba0
// TClosePicture::`scalar deleting destructor'

TClosePicture::~TClosePicture() {}

// FUNCTION: IMPERIALISM 0x00586bf0
void TClosePicture::vmethod_0072(int arg1, int arg2, int arg3, int arg4) {
  reinterpret_cast<int(__fastcall*)(void*, int, int, int, int)>(
      ::DispatchUiMouseEventToChildrenOrSelf)(this, arg1, arg2, arg3, arg4);
  TAmtBar* control = reinterpret_cast<TAmtBar*>(OwnerPanel());
  if (control != 0) {
    control->ApplyStyleDescriptor(reinterpret_cast<void*>(controlTag), 1);
  }
}
