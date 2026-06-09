#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/TGreatPower.h"
#include "game/win_rect.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"

#include "game/TAmtBar.h"
#include "game/TProductionCluster.h"

#include "game/GameAssert.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"

#include <new>

undefined4 thunk_DispatchPanelControlEvent(void);

// FUNCTION: IMPERIALISM 0x00586920
TProductionCluster::TProductionCluster()
    : TUberCluster(), field88(0), field8c(0), field8e(0), field90(0), field94(0) {}

// SYNTHETIC: IMPERIALISM 0x00586970
// TProductionCluster::`scalar deleting destructor'
TProductionCluster::~TProductionCluster() {}

// FUNCTION: IMPERIALISM 0x00586a60
void TProductionCluster::ApplyMoveValue(int value) {
  field8c = value;
}

// FUNCTION: IMPERIALISM 0x00586ab0
int TProductionCluster::NotifyControlSelectionChange(void* boundEntry, int arg2) {
  field8e = (int)boundEntry;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00586a80
int TProductionCluster::GetControlFlag(int value90, int value94) {
  field90 = value90;
  field94 = value94;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005869c0
void TProductionCluster::HandleValuePanelSplitArrowCommand(int commandId, void* eventArg,
                                                           int eventExtra) {
  TAmtBar* valueControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(0x76616c75));
  if (valueControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, commandId, eventArg, eventExtra);
}

// FUNCTION: IMPERIALISM 0x00586840
TProductionCluster* __cdecl CreateTProductionClusterInstance(void) {
  TProductionCluster* cluster = reinterpret_cast<TProductionCluster*>(
      AllocateWithFallbackHandler(sizeof(TProductionCluster)));
  if (cluster != 0) {
    new (cluster) TProductionCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586900
void* __cdecl GetTProductionClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(0x00662f20);
}

TProductionCluster* ConstructTProductionClusterBaseState(TProductionCluster* cluster) {
  new (cluster) TProductionCluster();
  return cluster;
}

TProductionCluster* DestructTProductionClusterAndMaybeFree(TProductionCluster* cluster,
                                                           unsigned char freeSelfFlag) {
  cluster->~TProductionCluster();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(cluster));
  }
  return cluster;
}
