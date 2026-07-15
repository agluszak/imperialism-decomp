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

void ApplySharedStringToControlState(CString sharedString, TView* control);
void AssignSharedStringToControlState(CString sharedString, TView* control);

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
void __cdecl DispatchToSelectableTextOptionEntries(TView* view, TControlPictureRectState* state,
                                                   int flag) {
  if (view->IsKindOf(RUNTIME_CLASS(TStaticText))) {
    view->AssertValid();
    static_cast<TControl*>(view)->SetCityProductionDialogPictureRectAndMaybeRefresh(state, flag);
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

// FUNCTION: IMPERIALISM 0x005c4590
void __cdecl ApplyUiTextStyleAndThemeFlags(TDropShadowText* control, int unused, int pointSize,
                                           int shadowThemeCode, int textThemeCode) {
  TControlPictureRectState styleDescriptor;
  styleDescriptor.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, pointSize, textThemeCode);
  control->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
  MapUiThemeCodeToStyleFlags(static_cast<short>(shadowThemeCode), &control->shadowThemeCode94);
}

// FUNCTION: IMPERIALISM 0x005c46b0
void LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(short group, short index,
                                                           unsigned int controlTag) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  ApplySharedStringToControlState(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4780
void LoadUiStringByGroupAndIndexToGlobalControlTag(short group, short index,
                                                   unsigned int controlTag) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  AssignSharedStringToControlState(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4850
void LoadUiStringByGroupAndIndexToControlObject(short group, short index, TView* control) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  ApplySharedStringToControlState(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4910
void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  AssignSharedStringToControlState(text, control);
}

// FUNCTION: IMPERIALISM 0x005c49d0
void ApplySharedStringToControlState(CString sharedString, TView* control) {
  control->EnableAndProcessFlag(sharedString);
}

// FUNCTION: IMPERIALISM 0x005c4a40
void AssignSharedStringToControlState(CString sharedString, TView* control) {
  control->EnableAndProcessFlag(sharedString);
}

// FUNCTION: IMPERIALISM 0x005c4ab0
TView* __cdecl ApplySharedStringToGlobalControlTag(CString sharedString, unsigned int controlTag) {
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  control->AssertValid();
  ApplySharedStringToControlState(sharedString, control);
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4b70
TView* __cdecl AssignSharedStringToTaggedControlAndProcessState(const char* text,
                                                                unsigned int controlTag) {
  CString sharedString(text);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  control->AssertValid();
  AssignSharedStringToControlState(sharedString, control);
  return control;
}
