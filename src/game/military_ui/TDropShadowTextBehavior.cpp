#include "game/military_ui/TDropShadowTextBehavior.h"

#include "game/ui_core/TStaticText.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_tags_widgets.h"
// SYNTHETIC: IMPERIALISM 0x004b0fe0
// TDropShadowTextBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b1080
// TDropShadowTextBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDropShadowTextBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x004b10a0
TDropShadowTextBehavior::TDropShadowTextBehavior() : TBehavior(), shadowColor10(0) {}

// SYNTHETIC: IMPERIALISM 0x004b10d0
// TDropShadowTextBehavior::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b1100
TDropShadowTextBehavior::~TDropShadowTextBehavior() {}

// FUNCTION: IMPERIALISM 0x004b1120
void TDropShadowTextBehavior::IDropShadowTextBehavior(COLORREF shadowColor) {
  shadowColor10 = shadowColor;
  SetBehaviorTag(IMPERIALISM_FOURCC('d', 'r', 'o', 'p'));
}

// FUNCTION: IMPERIALISM 0x004b1150
void TDropShadowTextBehavior::Draw(RECT* bounds) {
  (void)bounds;
  TStaticText* textOwner = static_cast<TStaticText*>(owner);
  SetQuickDrawColorAndPropagateIfChanged(shadowColor10);

  CString text;
  textOwner->CopyTextTo(&text);

  CRect shadowBounds;
  textOwner->BuildInsetContentRect(&shadowBounds);
  shadowBounds.top--;
  shadowBounds.bottom--;
  shadowBounds.left--;
  shadowBounds.right--;
  textOwner->DrawTextAligned(static_cast<LPCSTR>(text), text.GetLength(), &shadowBounds,
                             textOwner->textAlignmentCode);
}
