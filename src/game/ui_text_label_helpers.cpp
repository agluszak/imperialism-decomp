#include "game/CString.h"
#include "game/TDisplayMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TDropShadowText.h"
#include "game/CSubViewIterator.h"
#include "game/TStaticText.h"
#include "game/TView.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/quickdraw_rendering.h"
#include "game/global_data_tables.h"

void SetControlHoverHelpText(CString sharedString, TView* control);
void SetControlHoverHelpTextAltEntry(CString sharedString, TView* control);

// FUNCTION: IMPERIALISM 0x005c3d20
void MapUiThemeCodeToStyleFlags(short themeCode, int* outStyleFlags) {
  switch (themeCode) {
  case 0x2b67:
    *outStyleFlags = 0x1000000;
    return;
  case 0x2b68:
    *outStyleFlags = 0x1000013;
    return;
  case 0x2b6a:
    *outStyleFlags = 0x100005c;
    return;
  case 0x2b6b:
    *outStyleFlags = 0x10000d2;
    return;
  case 0x2b69:
    *outStyleFlags = 0x10000cb;
    return;
  case 0x2b6c:
    *outStyleFlags = 0x1000028;
    return;
  case 0x2b6d:
    *outStyleFlags = 0x1000001;
    return;
  case 0x2b6e:
    *outStyleFlags = 0x1000001;
    return;
  case 0x2b6f:
    *outStyleFlags = 0x100002a;
    return;
  case 0x2b70:
    *outStyleFlags = 0x10000c9;
    return;
  case 0x2b71:
    *outStyleFlags = 0x100001b;
    return;
  case 0x2b72:
    *outStyleFlags = 0x1000030;
    return;
  case 0x2b73:
    *outStyleFlags = 0x10000c8;
    return;
  case 0x2b74:
    *outStyleFlags = 0x10000e3;
    return;
  default:
    *outStyleFlags = (themeCode & 0xffff) | 0x1000000;
    return;
  }
}

// FUNCTION: IMPERIALISM 0x005c3e80
void BuildUiTextStyleDescriptor(TUiTextStyleDescriptor* styleDescriptor, int unused, int arg2,
                                int themeCode) {
  (void)unused;
  // Verified against 0x5c3e9b-0x5c3f01: constructed unconditionally, never read or
  // written again -- a genuinely dead local kept faithfully (not our porting
  // artifact; the original does the same).
  CString deadLocal;
  styleDescriptor->fontStyleFlags = 0;
  int styleFlags = 0;
  MapUiThemeCodeToStyleFlags(static_cast<short>(themeCode), &styleFlags);
  styleDescriptor->textColor = styleFlags;
  styleDescriptor->fontSize = static_cast<short>(arg2);
  styleDescriptor->fontFamily = (arg2 >= 0xc) ? 1 : 3;
}

// FUNCTION: IMPERIALISM 0x005c3f50
void InitializeUiTextStyleDescriptor(TUiTextStyleDescriptor* styleDescriptor, short face,
                                     short pointSize, int themeCode, short font) {
  // Same dead CString shape as BuildUiTextStyleDescriptor; the original constructs and
  // destroys it while only using the packed descriptor fields below.
  CString deadLocal;
  int styleFlags = 0;
  styleDescriptor->fontStyleFlags = face;
  MapUiThemeCodeToStyleFlags(static_cast<short>(themeCode), &styleFlags);
  styleDescriptor->fontSize = pointSize;
  styleDescriptor->textColor = styleFlags;
  styleDescriptor->fontFamily = font;
}

// FUNCTION: IMPERIALISM 0x005c4020
TStaticText* ApplyControlThemeStyleAndOptionalCaption(TStaticText* control, int unused2,
                                                      int pointSize, int themeCode, int themeCode2,
                                                      const char* caption) {
  (void)unused2;
  control->AssertValid();
  TUiTextStyleDescriptor styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
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
  TUiTextStyleDescriptor styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
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
void __cdecl DispatchToSelectableTextOptionEntries(TView* view, TUiTextStyleDescriptor* state,
                                                   int flag) {
  if (view->IsKindOf(RUNTIME_CLASS(TStaticText))) {
    view->AssertValid();
    static_cast<TControl*>(view)->SetTextStyleAndMaybeRefresh(state, flag);
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
  TUiTextStyleDescriptor styleDescriptor;
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
  TUiTextStyleDescriptor styleDescriptor;
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
  TUiTextStyleDescriptor styleDescriptor;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, textThemeCode);
  control->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
  MapUiThemeCodeToStyleFlags(static_cast<short>(shadowThemeCode), &control->shadowThemeCode94);
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
