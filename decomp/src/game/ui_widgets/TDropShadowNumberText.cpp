#include "game/ui_widgets/TDropShadowNumberText.h"

#include "game/ui_core/TEditText.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TDropShadowNumberText, TPictureNumberText)

// FUNCTION: IMPERIALISM 0x005b5910
TDropShadowNumberText::TDropShadowNumberText() : TPictureNumberText() {
  shadowColorAc = g_defaultDropShadowTextColor;
}

// FUNCTION: IMPERIALISM 0x005b5990
TDropShadowNumberText::~TDropShadowNumberText() {}

// FUNCTION: IMPERIALISM 0x005b59b0
void TDropShadowNumberText::Draw(RECT* rectBuffer) {
  TEditText::Draw(rectBuffer);
  SetQuickDrawColorAndPropagateIfChanged(shadowColorAc);
  CString shadowText;
  GetCurrentText(&shadowText);
  CRect shadowRect;
  BuildInsetContentRect(&shadowRect);
  shadowRect.top--;
  shadowRect.bottom--;
  shadowRect.left--;
  shadowRect.right--;
  ImageText((LPCSTR)shadowText, shadowText.GetLength(), &shadowRect, textAlignmentCode);
}
