#include "game/CString.h"
#include "game/TDisplayMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TDropShadowText.h"
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
