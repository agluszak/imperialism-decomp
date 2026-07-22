#pragma once

#include "game/CString.h"

class TDropShadowText;
class TDropShadowNumberText;
class TStaticText;
class TView;
struct TextStyle;

// --- Text-style / control-theme helpers (implemented in ui_text_label_helpers.cpp) ---
// Relocated here from quickdraw_rendering.h: these operate on the packed
// TextStyle text-style record and the 0x5c40xx control-theme path, not on
// the QuickDraw surface/font engine. (The font-engine consumers
// CreateFontFromPresetAndAttachRegionHandle / UpdateGlobalFontPresetAndRebuildCachedFontIfDirty
// stay in quickdraw_rendering.h with their own forward-decl.)

void MapUiThemeCodeToStyleFlags(short themeCode, int* outStyleFlags);
void BuildUiTextStyleDescriptor(TextStyle* styleDescriptor, int unused, int arg2, int themeCode);
void InitializeUiTextStyleDescriptor(TextStyle* styleDescriptor, short face, short pointSize,
                                     int themeCode, short font);

// 0x5c4020 -- asserts the text control, applies a theme style descriptor built from
// themeCode (BuildUiTextStyleDescriptor inline-expanded in the original), sets the
// text theme code, and optionally assigns a caption string. Returns the control.
// unused2 is always 0 at every known call site.
TStaticText* ApplyControlThemeStyleAndOptionalCaption(TStaticText* control, int unused2,
                                                      int pointSize, int themeCode, int themeCode2,
                                                      const char* caption);

// 0x5c4180 -- same shape as ApplyControlThemeStyleAndOptionalCaption, but the caption
// text is loaded from a string-table resource (group/index) via
// g_pModuleLibraryCacheState instead of being passed as a literal pointer.
TStaticText* ConfigureUiControlStyleValueAndCaptionFromStringResource(TStaticText* control,
                                                                      int unused2, int pointSize,
                                                                      int themeCode, int themeCode2,
                                                                      int stringResourceGroup,
                                                                      short stringResourceIndex);

void ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(int unused, int styleWidth, int themeCode);
void InitializeUiTextStyleDescriptorAndApplyQuickDraw(short face, short pointSize, int themeCode,
                                                      short font);

// 0x5c49d0 / 0x5c4a40: set a control's cursor hover-help text -- both forward `text`
// (by value) to TView::SetHoverHelpText, which stores it in hoverHelpText58 and sets
// hoverHelpEnabled5c; TView::DoSetCursor later sends that string + the
// control rect to g_pCursorControlPanel. Two separate original addresses with identical
// bodies (do NOT merge -- likely distinct source functions or linker-fold candidates).
void SetControlHoverHelpText(CString text, TView* control);
void SetControlHoverHelpTextAltEntry(CString text, TView* control);

void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control);

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

// 0x5c4620: numeric-text sibling of ApplyUiTextStyleAndThemeFlags. The numeric control's
// drop-shadow theme field is at +0xac rather than TDropShadowText's +0x94.
void __cdecl ApplyUiNumberTextStyleAndThemeColor(TDropShadowNumberText* control, int unused,
                                                 int pointSize, int shadowThemeCode,
                                                 int textThemeCode);

void LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(short group, short index,
                                                           unsigned int controlTag);

void LoadUiStringByGroupAndIndexToGlobalControlTag(short group, short index,
                                                   unsigned int controlTag);

class TView;

// 0x5c4ab0: resolve `controlTag` on the active dialog, assert it, then apply the
// shared string through the normal control-state path.
TView* __cdecl ApplySharedStringToGlobalControlTag(CString sharedString, unsigned int controlTag);

// 0x5c4850: load string (group,index) from the module library cache and apply it to the
// control via SetControlHoverHelpText.
void LoadUiStringByGroupAndIndexToControlObject(short group, short index, TView* control);

// 0x5c4b70: build a CString from `text`, resolve `controlTag` on the active dialog, assert
// it, then assign the shared string through the normal control-state path.
TView* __cdecl AssignSharedStringToTaggedControlAndProcessState(const char* text,
                                                                unsigned int controlTag);
