#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
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
void TCityBarCluster::ApplyMoveValue(TCity* city) {
  TGreatPower* nation = city->ownerNationAc;
  TPopulationMgr* population = city->productionSummary1d8;

  TNumberText* areaControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagTrea));
  if (areaControl != 0) {
    areaControl->SetControlValue(nation->treasuryValue10, 1);
    areaControl->Show(0, 1);
  }

  TNumberText* returnControl =
      static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagUntr));
  if (returnControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryRtnu);
  }
  returnControl->SetControlValue(population->baselineSlots10->lowSkillCount04, 1);

  TNumberText* airControl = static_cast<TNumberText*>(this->ResolveControlByTag(kSummaryTagTrai));
  if (airControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryIart);
  }
  airControl->SetControlValue(population->baselineSlots10->mediumSkillCount06, 1);

  TNumberText* profControl = static_cast<TNumberText*>(this->ResolveControlByTag(kSummaryTagProf));
  if (profControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryProf);
  }
  profControl->SetControlValue(population->baselineSlots10->highSkillCount08, 1);
}

void TCityBarCluster::UpdateTradeSummaryMetricControlsFromRecord(TCity* city) {
  ApplyMoveValue(city);
}
