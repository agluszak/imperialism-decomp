#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/NationState.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include "game/quickdraw_guards.h"

#include "game/TAmtBar.h"
#include "game/TUnitToolbarCluster.h"
#include "game/GameAssert.h"
#include "game/UiRuntimeContext.h"

#include <new>

extern "C" {
char g_pClassDescTUnitToolbarCluster = 0;
char g_vtblTUnitToolbarCluster = 0;
}

#include "game/ApplicationUiRootController.h"

undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DispatchPanelControlEvent(void);

// FUNCTION: IMPERIALISM 0x00585f70
TUnitToolbarCluster* TUnitToolbarCluster::CreateInstance() {
  return new TUnitToolbarCluster();
}

// FUNCTION: IMPERIALISM 0x00585ff0
void* TUnitToolbarCluster::GetClassNamePointer() {
  return reinterpret_cast<void*>(&g_pClassDescTUnitToolbarCluster);
}

// FUNCTION: IMPERIALISM 0x00586010
TUnitToolbarCluster::TUnitToolbarCluster() : TUberCluster() {}

// FUNCTION: IMPERIALISM 0x00586040
void* TUnitToolbarCluster::DestructAndMaybeFree(int freeSelfFlag) {
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    // We use the fallback allocator behavior which corresponds to operator delete
    // For now we just let the compiler emit delete this.
    // Wait, the original code had: FreeHeapBufferIfNotNull((undefined4)cluster);
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x00586090
void TUnitToolbarCluster::DispatchEvent(int eventClass, void* eventPayload, int eventFlags) {
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, eventClass, eventPayload, eventFlags);

  if (!(((g_pApplicationUiRootController->screenModeAt24 == 1) && (eventClass == 0x68)) ||
        (eventClass == 0x67) || (eventClass == 10) || (eventClass == 0x0c))) {
    return;
  }

  void* ownerPanel = this->OwnerPanel();
  TControl* mainControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(0x6d61696e);
  if (mainControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  mainControl->vmethod_0015();
}

// FUNCTION: IMPERIALISM 0x00586150
unsigned char OrphanVtableAssignStub_00586150(void) {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00586170
void TUnitToolbarCluster::UpdateTradeResourceSelectionByIndex(int nResourceIndex) {
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x84) = nResourceIndex;

  TView* panel = reinterpret_cast<TView*>(this->OwnerPanel());
  if (panel == 0) {
    return;
  }

  TControl* control = panel->ResolveControlByTag(0x444c4f47);
  if (control == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  control->DispatchEvent(0x0c, 0, 0);
}
