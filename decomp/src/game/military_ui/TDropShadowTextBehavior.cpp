#include "game/military_ui/TDropShadowTextBehavior.h"

#include "game/ui_core/TStaticText.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_tags_widgets.h"

IMPLEMENT_DYNCREATE(TDropShadowTextBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x004b10a0
TDropShadowTextBehavior::TDropShadowTextBehavior() : shadowColor(0) {}

// FUNCTION: IMPERIALISM 0x004b1120
void TDropShadowTextBehavior::IDropShadowTextBehavior(COLORREF shadowColor) {
  this->shadowColor = shadowColor;
  SetBehaviorTag(IMPERIALISM_FOURCC('d', 'r', 'o', 'p'));
}

// FUNCTION: IMPERIALISM 0x004b1150
void TDropShadowTextBehavior::Draw(RECT* bounds) {
  TStaticText* textOwner = static_cast<TStaticText*>(owner);
  SetQuickDrawColorAndPropagateIfChanged(shadowColor);

  CString text;
  textOwner->CopyTextTo(&text);

  CRect shadowBounds;
  textOwner->BuildInsetContentRect(&shadowBounds);
  shadowBounds.top--;
  shadowBounds.bottom--;
  shadowBounds.left--;
  shadowBounds.right--;
  textOwner->ImageText(static_cast<LPCSTR>(text), text.GetLength(), &shadowBounds,
                       textOwner->textAlignmentCode);
}
