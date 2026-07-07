#include "game/TDropShadowText.h"

#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x005b54a0
// TDropShadowText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b5570
// TDropShadowText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDropShadowText, TPictureText)

// FUNCTION: IMPERIALISM 0x005b5590
TDropShadowText::TDropShadowText() : TPictureText(), shadowThemeCode94(0) {}

// SYNTHETIC: IMPERIALISM 0x005b5600
// TDropShadowText::`scalar deleting destructor'
TDropShadowText::~TDropShadowText() {}

// FUNCTION: IMPERIALISM 0x005b5650
void TDropShadowText::ApplyRectSlot110(RECT* rectBuffer) {
  TStaticText::ApplyRectSlot110(rectBuffer);
  SetQuickDrawColorAndSyncGlobals(shadowThemeCode94);
  CString textBuffer;
  AssignSharedStringFromField84(&textBuffer);
  RECT shadowRect;
  BuildRectFromSlot158(&shadowRect);
  shadowRect.left--;
  shadowRect.top--;
  shadowRect.right--;
  shadowRect.bottom--;
  RenderControlStateTextBySelectionCode((LPCSTR)textBuffer, textBuffer.GetLength(), &shadowRect,
                                        field90);
}
