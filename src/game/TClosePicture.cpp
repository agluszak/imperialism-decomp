#include "game/TAmtBar.h"
#include "game/TClosePicture.h"

namespace {

// GLOBAL: IMPERIALISM 0x662f38
extern "C" CRuntimeClass g_pClassDescTClosePicture = {nullptr, 0, 0, nullptr, nullptr};

} // namespace

// FUNCTION: IMPERIALISM 0x00586ad0
TClosePicture* __cdecl CreateTClosePictureInstance(void) {
  return new TClosePicture();
}

// MFC RTTI slot 0x00 override: return this class's CRuntimeClass descriptor (0x662f38).
// FUNCTION: IMPERIALISM 0x00586b50
CRuntimeClass* TClosePicture::GetRuntimeClass() {
  return &g_pClassDescTClosePicture;
}

// FUNCTION: IMPERIALISM 0x00586b70
TClosePicture::TClosePicture() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00586ba0
// TClosePicture::`scalar deleting destructor'

TClosePicture::~TClosePicture() {}

// FUNCTION: IMPERIALISM 0x00586bf0
#pragma optimize("y", on)
char TClosePicture::DispatchUiMouseEventToChildrenOrSelf_Impl(Point32* point, int arg2, int arg3,
                                                              int arg4) {
  char result = TControl::DispatchUiMouseEventToChildrenOrSelf_Impl(point, arg2, arg3, arg4);
  TAmtBar* control = reinterpret_cast<TAmtBar*>(OwnerPanel());
  if (control != 0) {
    control->ApplyStyleDescriptor(reinterpret_cast<void*>(controlTag), 1);
  }
  return result;
}
#pragma optimize("", off)
