#pragma once

// Shared build-stack wrappers for the split turn_event_dialog_factory_*.cpp TUs.
// static __inline so /Ob1 folds them into each builder exactly as in the former
// monolith; they reproduce the original CList COMDAT AddTail/RemoveTail calls.

#include "game/TView.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

static __inline void PushUiWidgetBuildStackNode(TView* node) {
  POSITION (CList<TView*, TView*>::*addTail)(TView*) = &CList<TView*, TView*>::AddTail;
  (g_UiWidgetBuildStack006a13e0.*addTail)(node);
}

static __inline void PopUiWidgetBuildStackNode() {
  TView* (CList<TView*, TView*>::*removeTail)() = &CList<TView*, TView*>::RemoveTail;
  (g_UiWidgetBuildStack006a13e0.*removeTail)();
}
