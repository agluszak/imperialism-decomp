#include "game/core/CString.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/TResourceMgr.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_widgets/TDropShadowNumberText.h"
#include "game/CSubViewIterator.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

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
void BuildUiTextStyleDescriptor(TextStyle* styleDescriptor, int unused, int fontSize,
                                short themeCode) {
  CString deadLocal;
  styleDescriptor->fontStyleFlags = 0;
  COLORREF textColor = 0;
  ResolveUiThemeColor(themeCode, &textColor);
  styleDescriptor->textColor = textColor;
  styleDescriptor->fontSize = static_cast<short>(fontSize);
  styleDescriptor->fontFamily = (fontSize >= 0xc) ? 1 : 3;
}

// FUNCTION: IMPERIALISM 0x005c3f50
void InitializeUiTextStyleDescriptor(TextStyle* styleDescriptor, short face, short pointSize,
                                     short themeCode, short font) {
  CString deadLocal;
  COLORREF textColor = 0;
  styleDescriptor->fontStyleFlags = face;
  ResolveUiThemeColor(themeCode, &textColor);
  styleDescriptor->fontSize = pointSize;
  styleDescriptor->textColor = textColor;
  styleDescriptor->fontFamily = font;
}

// FUNCTION: IMPERIALISM 0x005c4020
TStaticText* ApplyControlTheme(TStaticText* control, int unused2, int pointSize, int themeCode,
                               short themeCode2, const char* caption) {
  control->AssertValid();
  TextStyle styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  control->SetJustification(themeCode2, false);
  if (caption != 0) {
    CString captionString(caption);
    control->SetTextAndMaybeRefresh(&captionString, false);
  }
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4180
TStaticText* ConfigureControlFromStrings(TStaticText* control, int unused2, int pointSize,
                                         int themeCode, short themeCode2, int stringResourceGroup,
                                         short stringResourceIndex) {
  CString caption;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&caption, stringResourceGroup,
                                                      stringResourceIndex);
  control->AssertValid();
  TextStyle styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  control->SetJustification(themeCode2, false);
  if (static_cast<LPCSTR>(caption) != 0) {
    control->SetTextAndMaybeRefresh(&caption, false);
  }
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4310
TStaticText* __cdecl RefreshAndTheme(unsigned int controlTag, int unused2, int pointSize,
                                     int themeCode, int themeCode2, const char* caption) {
  TView* control = g_pDisplayMgr->activeDialog->FindSubView(controlTag);
  control->AssertValid();
  return ApplyControlTheme(static_cast<TStaticText*>(control), unused2, pointSize, themeCode,
                           themeCode2, caption);
}

// Dead helper (no live callers): the bare tag-resolve form the siblings above wrap.
// FUNCTION: IMPERIALISM 0x005c4380
TView* __cdecl ResolveControlByTagInActiveDialog(unsigned int controlTag) {
  return g_pDisplayMgr->activeDialog->FindSubView(controlTag);
}

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
void ApplyTextStyle(int unused, int styleWidth, int themeCode) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, styleWidth, themeCode);
  SetQuickDrawTextFace(styleDescriptor.fontStyleFlags);
  SetQuickDrawTextSize(styleDescriptor.fontSize);
  SetQuickDrawTextFont(styleDescriptor.fontFamily);
  SetQuickDrawColorAndSyncGlobals(styleDescriptor.textColor);
}

// FUNCTION: IMPERIALISM 0x005c4500
void SetTextStyleAndApply(short face, short pointSize, int themeCode, short font) {
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
                                           short shadowThemeCode, int textThemeCode) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, textThemeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  ResolveUiThemeColor(shadowThemeCode, &control->shadowColor);
}

// FUNCTION: IMPERIALISM 0x005c4620
void __cdecl ApplyUiNumberTextStyleAndThemeColor(TDropShadowNumberText* control, int unused,
                                                 int pointSize, short shadowThemeCode,
                                                 int textThemeCode) {
  TextStyle styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, textThemeCode);
  control->InstallTextStyle(styleDescriptor, 0);
  ResolveUiThemeColor(shadowThemeCode, &control->shadowColor);
}

// FUNCTION: IMPERIALISM 0x005c46b0
void SetTaggedStringAndApply(short group, short index, unsigned int controlTag) {
  CString text;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->FindSubView(controlTag);
  SetControlHoverHelpText(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4780
void SetTaggedString(short group, short index, unsigned int controlTag) {
  CString text;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->FindSubView(controlTag);
  SetControlHoverHelpTextAltEntry(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4850
void SetControlString(short group, short index, TView* control) {
  CString text;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  SetControlHoverHelpText(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4910
void SendStringCommand(short group, short index, TView* control) {
  CString text;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&text, group, index);
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
  TView* control = g_pDisplayMgr->activeDialog->FindSubView(controlTag);
  control->AssertValid();
  SetControlHoverHelpText(sharedString, control);
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4b70
TView* __cdecl SetTaggedControlText(const char* text, unsigned int controlTag) {
  CString sharedString(text);
  TView* control = g_pDisplayMgr->activeDialog->FindSubView(controlTag);
  control->AssertValid();
  SetControlHoverHelpTextAltEntry(sharedString, control);
  return control;
}
