#pragma once

#include "game/CString.h"

class TDropShadowText;
class TStaticText;
class TView;

// 0x5c49d0: apply a shared/string caption to a control (sets the text state).  Callee
// consumes `sharedString` by value; `control` is asserted and updated.
void ApplySharedStringToControlState(CString sharedString, TView* control);

// 0x5c4310: resolve `controlTag` on g_pDisplayMgr->activeDialog, AssertValid it, and
// forward to ApplyControlThemeStyleAndOptionalCaption. Genuine __cdecl free function
// (callers clean 0x18). Body TODO.
TStaticText* __cdecl RefreshActiveControlThenApplyThemeStyleAndCaption(unsigned int controlTag,
                                                                       int unused2, int pointSize,
                                                                       int themeCode,
                                                                       int themeCode2,
                                                                       const char* caption);

// 0x5c4590: build a text-style descriptor for (pointSize, textThemeCode), apply it to
// the control, and map shadowThemeCode into the control's +0x94 shadow style flags.
void __cdecl ApplyUiTextStyleAndThemeFlags(TDropShadowText* control, int unused, int pointSize,
                                           int shadowThemeCode, int textThemeCode);
