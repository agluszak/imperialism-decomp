#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"
#include "screens/TransportScreen.h"

#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_tags_common.h"

namespace {

// The commodity row this scenario reads the hover help of. Which one does not matter -- the help
// text is built the same way for every row -- so the first is enough.
const short kFirstCommodityRow = 0;

// The transport ledger: open it from the map, check it presented itself, and leave.
//
// Everything asserted here is presentation the ledger builds once and never revisits: its column
// headings, the toolbar button's selected state, a commodity row's substituted hover help, and the
// capacity readout's value and placement. Each of those has been a regression at some point.
class TransportScreenTestCase : public EasyMapScriptScenario {
public:
protected:
  void Script() override {
    RT_BEGIN();

    // The ledger's root is a plain TPicture, so its identity comes from the turn event and its own
    // headings rather than from a view class -- which is what TransportScreen::IsCurrent checks.
    RT_ACTIVATE_AND_AWAIT("open the transport ledger", StrategicMap().OpenTransport(),
                          TransportScreen::IsCurrent(), kObserveUiStateChanged);

    RT_REQUIRE(Transport().HasLedgerHeadings());
    RT_REQUIRE(Transport().ToolbarIconIsSelected());
    RT_REQUIRE(Transport().CommodityHelpIsSubstituted(kFirstCommodityRow));
    // The capacity label is written by TTransportPicture::Draw→Refresh, so it only exists
    // once the gauge's first paint has been delivered.
    RT_AWAIT(Transport().CapacityLabelMatchesSplit(),
             kObservePaintCompleted | kObserveApplicationIdle);
    RT_REQUIRE(Transport().CapacityLabelHasRetailGeometry());
    RT_AWAIT(HasScenarioUiSnapshot(), kObserveUiStateChanged);

    // Moving an allocation off a commodity must go through the real order path: the row's
    // 'left' arrow drops its need target and frees the nation's reserved capacity by one.
    lowerableSlot = Transport().FirstLowerableCommoditySlot();
    RT_REQUIRE_NE(-1, lowerableSlot);
    targetBefore = Transport().CommodityNeedTarget(lowerableSlot);
    reservedBefore = Transport().ReservedTransportCapacity();
    RT_DO("lower one commodity's transport share",
          Transport().ClickCommodityArrow(lowerableSlot, kControlTagLeft));
    RT_REQUIRE_EQ(targetBefore - 1, Transport().CommodityNeedTarget(lowerableSlot));
    RT_REQUIRE_EQ(reservedBefore - 1, Transport().ReservedTransportCapacity());

    RT_CLOSE_TO_MAP("leave the transport ledger", Transport().Close());
    RT_PASS();

    RT_END();
  }

private:
  short lowerableSlot;
  short targetBefore;
  short reservedBefore;
};

} // namespace

RUNTIME_TEST_FACTORY(TransportScreenTestCase, TransportScreenTest)
