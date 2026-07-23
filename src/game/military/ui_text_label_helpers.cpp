#include "game/ui_screens/CString.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_widgets/TDropShadowNumberText.h"
#include "game/CSubViewIterator.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

void SetControlHoverHelpText(CString sharedString, TView* control);
void SetControlHoverHelpTextAltEntry(CString sharedString, TView* control);

// FUNCTION: IMPERIALISM 0x005c3d20
void ResolveUiThemeColor(short themeCode, COLORREF* outColor) {
  switch (themeCode) {
  case 0x2b67:
    *outColor = PALETTEINDEX(0);
    return;
  case 0x2b68:
    *outColor = PALETTEINDEX(0x13);
    return;
  case 0x2b6a:
    *outColor = PALETTEINDEX(0x5c);
    return;
  case 0x2b6b:
    *outColor = PALETTEINDEX(0xd2);
    return;
  case 0x2b69:
    *outColor = PALETTEINDEX(0xcb);
    return;
  case 0x2b6c:
    *outColor = PALETTEINDEX(0x28);
    return;
  case 0x2b6d:
    *outColor = PALETTEINDEX(1);
    return;
  case 0x2b6e:
    *outColor = PALETTEINDEX(1);
    return;
  case 0x2b6f:
    *outColor = PALETTEINDEX(0x2a);
    return;
  case 0x2b70:
    *outColor = PALETTEINDEX(0xc9);
    return;
  case 0x2b71:
    *outColor = PALETTEINDEX(0x1b);
    return;
  case 0x2b72:
    *outColor = PALETTEINDEX(0x30);
    return;
  case 0x2b73:
    *outColor = PALETTEINDEX(0xc8);
    return;
  case 0x2b74:
    *outColor = PALETTEINDEX(0xe3);
    return;
  default:
    *outColor = PALETTEINDEX(themeCode);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x005c3e80
void BuildUiTextStyleDescriptor(TextStyle* styleDescriptor, int unused, int arg2, int themeCode) {
  (void)unused;
  // Verified against 0x5c3e9b-0x5c3f01: constructed unconditionally, never read or
  // written again -- a genuinely dead local kept faithfully (not our porting
  // artifact; the original does the same).
  CString deadLocal;
  styleDescriptor->fontStyleFlags = 0;
  COLORREF textColor = 0;
  ResolveUiThemeColor(static_cast<short>(themeCode), &textColor);
  styleDescriptor->textColor = textColor;
  styleDescriptor->fontSize = static_cast<short>(arg2);
  styleDescriptor->fontFamily = (arg2 >= 0xc) ? 1 : 3;
}

// FUNCTION: IMPERIALISM 0x005c3f50
void InitializeUiTextStyleDescriptor(TextStyle* styleDescriptor, short face, short pointSize,
                                     int themeCode, short font) {
  // Same dead CString shape as BuildUiTextStyleDescriptor; the original constructs and
  // destroys it while only using the packed descriptor fields below.
  CString deadLocal;
  COLORREF textColor = 0;
  styleDescriptor->fontStyleFlags = face;
  ResolveUiThemeColor(static_cast<short>(themeCode), &textColor);
  styleDescriptor->fontSize = pointSize;
  styleDescriptor->textColor = textColor;
  styleDescriptor->fontFamily = font;
}

// FUNCTION: IMPERIALISM 0x005c4020
TStaticText* ApplyControlThemeStyleAndOptionalCaption(TStaticText* control, int unused2,
                                                      int pointSize, int themeCode, int themeCode2,
                                                      const char* caption) {
  (void)unused2;
  control->AssertValid();
  TextStyle styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  control->SetTextAlignmentAndMaybeRefresh(static_cast<short>(themeCode2), 0);
  if (caption != 0) {
    CString captionString(caption);
    control->SetTextAndMaybeRefresh(&captionString, 0);
  }
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4180
TStaticText* ConfigureUiControlStyleValueAndCaptionFromStringResource(TStaticText* control,
                                                                      int unused2, int pointSize,
                                                                      int themeCode, int themeCode2,
                                                                      int stringResourceGroup,
                                                                      short stringResourceIndex) {
  (void)unused2;
  CString caption;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&caption, stringResourceGroup,
                                                                  stringResourceIndex);
  control->AssertValid();
  TextStyle styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  control->SetTextAlignmentAndMaybeRefresh(static_cast<short>(themeCode2), 0);
  if (static_cast<LPCSTR>(caption) != 0) {
    control->SetTextAndMaybeRefresh(&caption, 0);
  }
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4310
TStaticText* __cdecl RefreshActiveControlThenApplyThemeStyleAndCaption(unsigned int controlTag,
                                                                       int unused2, int pointSize,
                                                                       int themeCode,
                                                                       int themeCode2,
                                                                       const char* caption) {
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  control->AssertValid();
  return ApplyControlThemeStyleAndOptionalCaption(static_cast<TStaticText*>(control), unused2,
                                                  pointSize, themeCode, themeCode2, caption);
}

// Recursively applies a picture-rect/theme state to every TStaticText control in `view`'s
// subtree: if `view` itself is a TStaticText it gets the state, then each subview is visited
// via the shared CSubViewIterator (which recurses into their subviews in turn).
// FUNCTION: IMPERIALISM 0x005c43b0
void __cdecl DispatchToSelectableTextOptionEntries(TView* view, TextStyle* state, int flag) {
  if (view->IsKindOf(RUNTIME_CLASS(TStaticText))) {
    view->AssertValid();
    static_cast<TControl*>(view)->InstallTextStyle(*state, flag);
  }
  CSubViewIterator iter(view);
  TView* child = iter.FirstSubView();
  if (iter.MoreSubViews()) {
    do {
      DispatchToSelectableTextOptionEntries(child, state, flag);
      child = iter.NextSubView();
    } while (iter.MoreSubViews());
  }
}

// FUNCTION: IMPERIALISM 0x005c4470
void ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(int unused, int styleWidth, int themeCode) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, styleWidth, themeCode);
  SetQuickDrawTextFace(styleDescriptor.fontStyleFlags);
  SetQuickDrawTextSize(styleDescriptor.fontSize);
  SetQuickDrawTextFont(styleDescriptor.fontFamily);
  SetQuickDrawColorAndSyncGlobals(styleDescriptor.textColor);
}

// FUNCTION: IMPERIALISM 0x005c4500
void InitializeUiTextStyleDescriptorAndApplyQuickDraw(short face, short pointSize, int themeCode,
                                                      short font) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  InitializeUiTextStyleDescriptor(&styleDescriptor, face, pointSize, themeCode, font);
  SetQuickDrawTextFace(styleDescriptor.fontStyleFlags);
  SetQuickDrawTextSize(styleDescriptor.fontSize);
  SetQuickDrawTextFont(styleDescriptor.fontFamily);
  SetQuickDrawColorAndSyncGlobals(styleDescriptor.textColor);
}

// FUNCTION: IMPERIALISM 0x005c4590
void __cdecl ApplyUiTextStyleAndThemeFlags(TDropShadowText* control, int unused, int pointSize,
                                           int shadowThemeCode, int textThemeCode) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, textThemeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  ResolveUiThemeColor(static_cast<short>(shadowThemeCode), &control->shadowColor94);
}

// FUNCTION: IMPERIALISM 0x005c4620
void __cdecl ApplyUiNumberTextStyleAndThemeColor(TDropShadowNumberText* control, int unused,
                                                 int pointSize, int shadowThemeCode,
                                                 int textThemeCode) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, textThemeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  ResolveUiThemeColor(static_cast<short>(shadowThemeCode), &control->shadowColorAc);
}

// FUNCTION: IMPERIALISM 0x005c46b0
void LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(short group, short index,
                                                           unsigned int controlTag) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  SetControlHoverHelpText(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4780
void LoadUiStringByGroupAndIndexToGlobalControlTag(short group, short index,
                                                   unsigned int controlTag) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  SetControlHoverHelpTextAltEntry(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4850
void LoadUiStringByGroupAndIndexToControlObject(short group, short index, TView* control) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  SetControlHoverHelpText(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4910
void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  SetControlHoverHelpTextAltEntry(text, control);
}

// FUNCTION: IMPERIALISM 0x005c49d0
void SetControlHoverHelpText(CString sharedString, TView* control) {
  control->SetHoverHelpText(sharedString);
}

// FUNCTION: IMPERIALISM 0x005c4a40
void SetControlHoverHelpTextAltEntry(CString sharedString, TView* control) {
  control->SetHoverHelpText(sharedString);
}

// FUNCTION: IMPERIALISM 0x005c4ab0
TView* __cdecl ApplySharedStringToGlobalControlTag(CString sharedString, unsigned int controlTag) {
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  control->AssertValid();
  SetControlHoverHelpText(sharedString, control);
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4b70
TView* __cdecl AssignSharedStringToTaggedControlAndProcessState(const char* text,
                                                                unsigned int controlTag) {
  CString sharedString(text);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  control->AssertValid();
  SetControlHoverHelpTextAltEntry(sharedString, control);
  return control;
}
