#include "game/ui_widgets/TDropShadowNumberText.h"

#include "game/ui_core/TEditText.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x005b5820
// TDropShadowNumberText::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b58f0
// TDropShadowNumberText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDropShadowNumberText, TPictureNumberText)

// In the binary the trivial TNumberText/TPictureNumberText ctor bodies are inlined here
// after the TEditText base ctor call; the out-of-line base ctor call this emits is an
// accepted codegen difference.
// FUNCTION: IMPERIALISM 0x005b5910
TDropShadowNumberText::TDropShadowNumberText() : TPictureNumberText() {
  shadowColorAc = g_defaultDropShadowTextColor;
}

// SYNTHETIC: IMPERIALISM 0x005b5960
// TDropShadowNumberText::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b5990
TDropShadowNumberText::~TDropShadowNumberText() {}

// slot 0x44 — Draw override: shadow pass in shadowColorAc, then the regular
// value-text render.
// FUNCTION: IMPERIALISM 0x005b59b0
void TDropShadowNumberText::Draw(RECT* rectBuffer) {
  TEditText::Draw(rectBuffer);
  SetQuickDrawColorAndPropagateIfChanged(shadowColorAc);
  CString shadowText;
  GetCurrentText(&shadowText);
  CRect shadowRect;
  BuildInsetContentRect(&shadowRect);
  // Decremented field by field: the original inlines four DECs (0x5b5a1e-0x5b5a3d)
  // rather than calling CRect::OffsetRect, which in MSVC500's MFC forwards to the
  // USER32 ::OffsetRect import.
  shadowRect.top--;
  shadowRect.bottom--;
  shadowRect.left--;
  shadowRect.right--;
  DrawTextAligned((LPCSTR)shadowText, shadowText.GetLength(), &shadowRect, textAlignmentCode);
}
