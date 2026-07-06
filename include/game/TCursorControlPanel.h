#pragma once

#include "game/TInfoBarText.h"

// The 'crus' cursor-info control (g_pCursorControlPanel, resolved via
// ResolveControlByTag(kControlTagCurs)). The UI factory registers 'crus' as a
// TInfoBarText (see turn_event_dialog_factory.cpp:671/1139 + the comment at :701 "a
// 'crus' TInfoBarText"); TViewMgr::UiRuntimeSlotF8 (0x5db780) confirms this directly —
// it calls InitializeMapHintTextStyleAndThemeFlags/ConstructTMapKeyBaseState_Impl/
// SetTextThemeCodeAndMaybeRefresh on it and writes cursorThemeCode9c/fieldA0 at exactly
// TInfoBarText's real offsets, so this is a genuine (not merely layout-compatible)
// TInfoBarText and real inheritance is used instead of a placeholder vtable.
//
// Residual open question (bd imperialism-decomp-hpd.8): TView::HandleCursorHoverFallback
// (0x0048c250) dispatches byte 0x200 (SetTextAndLayoutRect) with NO arguments — verified
// matching in both original and recomp — inconsistent with the 2-arg signature. Whether
// that reflects a distinct override or a quirk of that one call site is still unresolved;
// it doesn't affect the fields/methods used here.
class TCursorControlPanel : public TInfoBarText {};
