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

IMPLEMENT_DYNCREATE(TCityBarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586630
TCityBarCluster::TCityBarCluster() : TUberCluster() {}

// FUNCTION: IMPERIALISM 0x00586690
TCityBarCluster::~TCityBarCluster() {}

// FUNCTION: IMPERIALISM 0x005866b0
void TCityBarCluster::StuffValues(TCity* city) {
  TGreatPower* nation = city->ownerNation;
  TPopulationMgr* population = city->productionSummary;

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
  returnControl->SetControlValue(population->baselineSlots->lowSkillCount, 1);

  TNumberText* airControl = static_cast<TNumberText*>(this->ResolveControlByTag(kSummaryTagTrai));
  if (airControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryIart);
  }
  airControl->SetControlValue(population->baselineSlots->mediumSkillCount, 1);

  TNumberText* profControl = static_cast<TNumberText*>(this->ResolveControlByTag(kSummaryTagProf));
  if (profControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryProf);
  }
  profControl->SetControlValue(population->baselineSlots->highSkillCount, 1);
}
