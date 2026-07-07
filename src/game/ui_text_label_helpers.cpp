#include "game/CString.h"
#include "game/TDisplayMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TView.h"
#include "game/global_data_tables.h"

void ApplySharedStringToControlState(CString sharedString, TView* control);
void AssignSharedStringToControlState(CString sharedString, TView* control);

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
