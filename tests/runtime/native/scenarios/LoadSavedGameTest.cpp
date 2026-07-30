#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"

#include "game/assets/TAssetMgr.h"
#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// A retail save loads into a playable map: the turn is sane, the map view built both of the
// children the load path is responsible for, the viewport lands tile-aligned, and no commodity
// carries both a purchase and a sale in its history -- mixed history is the signature of a
// misread trade record rather than of a real game state.
class LoadSavedGameTestCase : public LoadedMapScriptScenario {
public:
  bool RecordsGameFlow() const override {
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE(g_pSimMgr->economicTurn >= 0);

    // The map view can exist a tick before its children do, so these wait rather than failing
    // outright; a genuinely absent child still fails, as a timeout naming the specific
    // condition instead of a spurious first-tick failure. Reported separately because they are
    // built by different paths.
    RT_AWAIT(StrategicMap().HasMiniMap(), kObserveUiStateChanged);
    RT_AWAIT(StrategicMap().HasEndTurnControl(), kObserveUiStateChanged);

    RT_REQUIRE(StrategicMap().HasDialog());
    RT_ACTION("centre the loaded viewport", StrategicMap().SetViewportCell(2, 2));
    RT_REQUIRE(ViewportIsTileAligned());

    RT_REQUIRE_EQ(-1, FirstResourceWithMixedTradeHistory());
    RT_PASS();

    RT_END();
  }

private:
  bool ViewportIsTileAligned() const {
    const int x = StrategicMap().ViewportOriginX();
    const int y = StrategicMap().ViewportOriginY();
    return x >= 0 && y >= 0 && (x & 0x3f) == 0;
  }

  // -1 when every commodity's history is consistent; otherwise the first offending resource,
  // so the assertion reports which one rather than only that one exists.
  short FirstResourceWithMixedTradeHistory() const {
    TGreatPower* player = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (player == 0) {
      return -1;
    }
    for (short resource = 0; resource < 0x11; ++resource) {
      bool sawPurchase = false;
      bool sawSale = false;
      short entryCount = player->GetTrackedSlotEntryCountLow(resource);
      for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
        short kind = 0;
        short value = 0;
        short targetNation = 0;
        int payload = 0;
        player->ReadTrackedSlotEntryFields(resource, ordinal, &kind, &value, &targetNation,
                                           &payload);
        sawPurchase = sawPurchase || kind == kTrackedSlotOfferEntry;
        sawSale = sawSale || kind == kTrackedSlotAcceptEntry;
      }
      if (sawPurchase && sawSale) {
        return resource;
      }
    }
    return -1;
  }
};

// The harness's fallback when IMPERIALISM_RUNTIME_TEST names a test this binary does not have.
// Failing loudly beats passing vacuously: a typo in the name would otherwise look like a green
// run of nothing.
class UnknownRuntimeTestCase : public ManagersReadyScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RT_FAIL("unknown compiled runtime test: IMPERIALISM_RUNTIME_TEST names a test that is not "
            "in this binary");
    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(LoadSavedGameTestCase, LoadSavedGameTest)
RUNTIME_TEST_FACTORY(UnknownRuntimeTestCase, UnknownRuntimeTest)
