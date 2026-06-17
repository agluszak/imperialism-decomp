#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/ui_widget_thunks.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"

#include "game/TAmtBar.h"
#include "game/TCityBarCluster.h"
#include "game/GameAssert.h"
#include <new>
#include "game/mfc.h"

extern "C" {
CRuntimeClass g_pClassDescTCityBarCluster = {nullptr, 0, 0, nullptr, nullptr};
char g_vtblTCityBarCluster = 0;
}

undefined4 thunk_DestructTShipAndFreeIfOwned(void);

static __inline void FailNilPointerInUSmallViews(int line) {
  FailNilPointerWithAssert("Z:\\src\\USmallViews.cpp", line);
}

undefined4 thunk_DestructEngineerDialogBaseState(void);

// FUNCTION: IMPERIALISM 0x00586590
TCityBarCluster* TCityBarCluster::CreateInstance() {
  return new TCityBarCluster();
}

// FUNCTION: IMPERIALISM 0x00586610
CRuntimeClass* TCityBarCluster::GetRuntimeClass() const {
  return &g_pClassDescTCityBarCluster;
}

// FUNCTION: IMPERIALISM 0x00586630
TCityBarCluster::TCityBarCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x00586660
// TCityBarCluster::`scalar deleting destructor'

const int kAssertLineTradeSummaryRtnu = 0x67d;
const int kAssertLineTradeSummaryIart = 0x682;
const int kAssertLineTradeSummaryProf = 0x687;

// FUNCTION: IMPERIALISM 0x005866b0
void TCityBarCluster::ApplyMoveValue(int value) {
  int recordContext = value;
  int recordNode = *reinterpret_cast<int*>(recordContext + 0xac);
  int metricContext = *reinterpret_cast<int*>(recordContext + 0x1d8);
  int metrics = *reinterpret_cast<int*>(metricContext + 0x10);

  TControl* areaControl = this->ResolveControlByTag(0x74726561);
  if (areaControl != 0) {
    areaControl->SetControlValue(*reinterpret_cast<int*>(recordNode + 0x10));
    areaControl->SetEnabled(0, 1);
  }

  TControl* returnControl = this->ResolveControlByTag(0x756e7472);
  if (returnControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryRtnu);
  }
  returnControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 4));

  TControl* airControl = this->ResolveControlByTag(0x74726169);
  if (airControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryIart);
  }
  airControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 6));

  TControl* profControl = this->ResolveControlByTag(0x70726f66);
  if (profControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryProf);
  }
  profControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 8));
}

void TCityBarCluster::UpdateTradeSummaryMetricControlsFromRecord(int recordContext) {
  ApplyMoveValue(recordContext);
}
