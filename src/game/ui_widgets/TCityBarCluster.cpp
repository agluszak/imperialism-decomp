#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TNumberText.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TCityBarCluster.h"
#include "game/GameAssert.h"
#include <new>

const int kAssertLineTradeSummaryRtnu = 0x67d;
const int kAssertLineTradeSummaryIart = 0x682;
const int kAssertLineTradeSummaryProf = 0x687;

// SYNTHETIC: IMPERIALISM 0x00586590
// TCityBarCluster::CreateObject
// SYNTHETIC: IMPERIALISM 0x00586610
// TCityBarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCityBarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586630
TCityBarCluster::TCityBarCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x00586660
// TCityBarCluster::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00586690
TCityBarCluster::~TCityBarCluster() {}

// FUNCTION: IMPERIALISM 0x005866b0
void TCityBarCluster::ApplyMoveValue(int value) {
  int recordContext = value;
  int recordNode = *reinterpret_cast<int*>(recordContext + 0xac);
  int metricContext = *reinterpret_cast<int*>(recordContext + 0x1d8);
  int metrics = *reinterpret_cast<int*>(metricContext + 0x10);

  TNumberText* areaControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagTrea));
  if (areaControl != 0) {
    areaControl->SetControlValue(*reinterpret_cast<int*>(recordNode + 0x10), 1);
    areaControl->SetEnabled(0, 1);
  }

  TNumberText* returnControl =
      static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagUntr));
  if (returnControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryRtnu);
  }
  returnControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 4), 1);

  TNumberText* airControl = static_cast<TNumberText*>(this->ResolveControlByTag(kSummaryTagTrai));
  if (airControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryIart);
  }
  airControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 6), 1);

  TNumberText* profControl = static_cast<TNumberText*>(this->ResolveControlByTag(kSummaryTagProf));
  if (profControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryProf);
  }
  profControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 8), 1);
}

void TCityBarCluster::UpdateTradeSummaryMetricControlsFromRecord(int recordContext) {
  ApplyMoveValue(recordContext);
}
