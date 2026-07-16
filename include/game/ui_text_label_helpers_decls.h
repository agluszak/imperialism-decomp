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
// (callers clean 0x18).
TStaticText* __cdecl RefreshActiveControlThenApplyThemeStyleAndCaption(unsigned int controlTag,
                                                                       int unused2, int pointSize,
                                                                       int themeCode,
                                                                       int themeCode2,
                                                                       const char* caption);

// 0x5c4590: build a text-style descriptor for (pointSize, textThemeCode), apply it to
// the control, and map shadowThemeCode into the control's +0x94 shadow style flags.
void __cdecl ApplyUiTextStyleAndThemeFlags(TDropShadowText* control, int unused, int pointSize,
                                           int shadowThemeCode, int textThemeCode);

void LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(short group, short index,
                                                           unsigned int controlTag);

class TView;

// 0x5c4ab0: resolve `controlTag` on the active dialog, assert it, then apply the
// shared string through the normal control-state path.
TView* __cdecl ApplySharedStringToGlobalControlTag(CString sharedString, unsigned int controlTag);

// 0x5c4850: load string (group,index) from the module library cache and apply it to the
// control via ApplySharedStringToControlState.
void LoadUiStringByGroupAndIndexToControlObject(short group, short index, TView* control);

// 0x5c49d0: forward the shared string (by value) to the control's EnableAndProcessFlag.
void ApplySharedStringToControlState(CString sharedString, TView* control);

// 0x5c4b70: build a CString from `text`, resolve `controlTag` on the active dialog, assert
// it, then assign the shared string through the normal control-state path.
TView* __cdecl AssignSharedStringToTaggedControlAndProcessState(const char* text,
                                                                unsigned int controlTag);
