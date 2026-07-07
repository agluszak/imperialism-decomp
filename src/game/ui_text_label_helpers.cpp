#include "game/CString.h"
#include "game/TDisplayMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TView.h"
#include "game/global_data_tables.h"

void RunEnableAndProcessFlagWithScopedSharedStringCleanup(CString sharedString, TView* control);
void EnableAndProcessFlagWithSharedStringCleanup(CString sharedString, TView* control);

// FUNCTION: IMPERIALISM 0x005c46b0
void LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(short group, short index,
                                                           unsigned int controlTag) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  RunEnableAndProcessFlagWithScopedSharedStringCleanup(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4780
void LoadUiStringByGroupAndIndexToGlobalControlTag(short group, short index,
                                                   unsigned int controlTag) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  TView* control = g_pDisplayMgr->activeDialog->ResolveControlByTag(controlTag);
  EnableAndProcessFlagWithSharedStringCleanup(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4850
void LoadUiStringByGroupAndIndexToControlObject(short group, short index, TView* control) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  RunEnableAndProcessFlagWithScopedSharedStringCleanup(text, control);
}

// FUNCTION: IMPERIALISM 0x005c4910
void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control) {
  CString text;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, group, index);
  EnableAndProcessFlagWithSharedStringCleanup(text, control);
}

// FUNCTION: IMPERIALISM 0x005c49d0
void RunEnableAndProcessFlagWithScopedSharedStringCleanup(CString sharedString, TView* control) {
  control->EnableAndProcessFlag(sharedString);
}

// FUNCTION: IMPERIALISM 0x005c4a40
void EnableAndProcessFlagWithSharedStringCleanup(CString sharedString, TView* control) {
  control->EnableAndProcessFlag(sharedString);
}
