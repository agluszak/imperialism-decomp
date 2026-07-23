#include "game/TAmtBar.h"
#include "game/TWindow.h"
#include "game/TClosePicture.h"

// SYNTHETIC: IMPERIALISM 0x00586ad0
// TClosePicture::CreateObject

// MFC RTTI slot 0x00 override: return this class's CRuntimeClass descriptor (0x662f38).
// SYNTHETIC: IMPERIALISM 0x00586b50
// TClosePicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TClosePicture, TPictureButton)

// FUNCTION: IMPERIALISM 0x00586b70
TClosePicture::TClosePicture() : TPictureButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00586ba0
// TClosePicture::`scalar deleting destructor'

TClosePicture::~TClosePicture() {}

// FUNCTION: IMPERIALISM 0x00586bf0
char TClosePicture::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  char result = TControl::HandleMouseUp(point, event, origin);
  TWindow* window = GetWindow();
  if (window != 0) {
    window->Dismiss(controlTag, 1);
  }
  return result;
}
