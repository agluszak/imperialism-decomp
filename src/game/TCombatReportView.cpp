// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058C830
CombatReportViewState* __cdecl CreateTCombatReportViewInstance(void) {
  CombatReportViewState* view =
      reinterpret_cast<CombatReportViewState*>(AllocateWithFallbackHandler(0xa0));
  if (view != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
    view->vftable = reinterpret_cast<void*>(&g_vtblTCombatReportView);
  }
  return view;
}

// FUNCTION: IMPERIALISM 0x0058C8B0
void* __cdecl GetTCombatReportViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCombatReportView);
}

// FUNCTION: IMPERIALISM 0x0058C8D0
CombatReportViewState* __fastcall ConstructTCombatReportViewBaseState(CombatReportViewState* view) {
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void*>(&g_vtblTCombatReportView);
  return view;
}

// FUNCTION: IMPERIALISM 0x0058C900
CombatReportViewState* __fastcall
DestructTCombatReportViewAndMaybeFree(CombatReportViewState* view, int unusedEdx,
                                      unsigned char freeSelfFlag) {
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
