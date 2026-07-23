#include "game/ui_widgets/TDropShadowNumberText.h"

#include "game/ui_core/TEditText.h"
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
TDropShadowNumberText::~TDropShadowNumberText() {}

// slot 0x44 — Draw override: shadow pass in shadowColorAc, then the regular
// value-text render.
// FUNCTION: IMPERIALISM 0x005b59b0
void TDropShadowNumberText::Draw(RECT* rectBuffer) {
  TEditText::Draw(rectBuffer);
  // TODO(partial 0x5b59b0): the original then sets the quickdraw color to shadowColorAc
  // (0x495030), formats the value CString via the text virtuals, and draws it offset by
  // one pixel before the normal pass. Ported as an honest partial pending the cached
  // text-engine class recovery (docs/TODO.md).
}
