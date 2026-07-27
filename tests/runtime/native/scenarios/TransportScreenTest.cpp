#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TTransportPicture.h"

#include <string.h>

namespace {

class TransportScreenTestCase : public RandomGameScenario {
public:
  TransportScreenTestCase() : phase(kActivateTransportScreen) {}

  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateTransportScreen;
    EnterScenarioStep("activating_transport_screen",
                      "easy_combined_map_ready_for_transport_screen");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kActivateTransportScreen) {
      ActivateTransportScreen();
    } else if (phase == kWaitForTransportScreen) {
      WaitForTransportScreen();
    } else if (phase == kReturnToMap) {
      ReturnToMap();
    } else {
      WaitForMap();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventTransport) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

private:
  enum Phase { kActivateTransportScreen, kWaitForTransportScreen, kReturnToMap, kWaitForMap };

  void ActivateTransportScreen() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before opening transport\"");
      return;
    }
    phase = kWaitForTransportScreen;
    EnterScenarioStep("waiting_for_transport_screen", "activate_transport_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateTransport()) {
      FailScenario("\"transport toolbar control is disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForTransportScreen() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventTransport || mainView == 0 ||
        mainView->ResolveControlByTag(kControlTagTitL) == 0) {
      WaitForScenarioTick("\"transport toolbar action did not activate the transport ledger\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"transport toolbar action opened an unexpected modal\"");
      return;
    }

    TPicture* transport =
        static_cast<TPicture*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagTran));
    if (transport == 0 || transport->glyphBase84 != 0x24f0 || transport->controlState64 != 0) {
      FailScenario("\"transport toolbar icon did not enter its selected presentation state\"");
      return;
    }

    TStaticText* leftTitle =
        static_cast<TStaticText*>(mainView->ResolveControlByTag(kControlTagTitL));
    TStaticText* rightTitle =
        static_cast<TStaticText*>(mainView->ResolveControlByTag(kControlTagTitR));
    CString expectedLeft;
    CString expectedRight;
    g_pSimMgr->GetString(0x2735, 5, &expectedLeft);
    g_pSimMgr->GetString(0x2735, 6, &expectedRight);
    if (leftTitle == 0 || rightTitle == 0 || leftTitle->text == 0 || rightTitle->text == 0 ||
        *leftTitle->text != expectedLeft || *rightTitle->text != expectedRight) {
      FailScenario("\"transport and ledger headings were not populated\"");
      return;
    }
    TView* commodity = mainView->ResolveControlByTag(GetTradeSummarySelectionTagByIndex(0));
    const char* commodityHelp =
        commodity == 0 ? 0 : static_cast<LPCSTR>(commodity->hoverHelpText58);
    if (commodityHelp == 0 || strstr(commodityHelp, "Warehouse:") == 0 ||
        strstr(commodityHelp, "Needed:") == 0 || strchr(commodityHelp, '[') != 0) {
      FailScenario("\"transport commodity help has corrupt Warehouse or Needed text\"");
      return;
    }
    TTransportPicture* total =
        static_cast<TTransportPicture*>(mainView->ResolveControlByTag(kControlTagTota));
    TStaticText* amount =
        total == 0 ? 0 : static_cast<TStaticText*>(total->ResolveControlByTag(kControlTagText));
    CString currentAmount;
    CString capacityAmount;
    CString expectedAmount;
    if (total != 0) {
      currentAmount.Format("%d", static_cast<int>(total->splitValue94));
      capacityAmount.Format("%d", static_cast<int>(total->splitValue96));
      expectedAmount = currentAmount + "  /  " + capacityAmount;
    }
    if (amount == 0 || amount->text == 0) {
      FailScenario("\"transport capacity amount label is missing\"");
      return;
    }
    if (*amount->text != expectedAmount) {
      FailScenario("\"transport capacity amount label has the wrong value\"");
      return;
    }
    if (amount->ownerLocalX != 0xa2 || amount->ownerLocalY != 0x14 ||
        amount->frameWidth34 != 0x3c || amount->frameHeight38 != 0xb) {
      FailScenario("\"transport capacity amount label has the wrong geometry\"");
      return;
    }
    if (!HasScenarioUiSnapshot()) {
      WaitForScenarioTick("\"transport UI tree was not captured\"");
      return;
    }
    if (ScenarioPhaseElapsedMs() < 1000) {
      RequestScenarioTick();
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_from_transport", "activate_transport_end_control");
    RequestScenarioTick();
  }

  void ReturnToMap() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->ResolveControlByTag(kControlTagTitL) == 0) {
      FailScenario("\"transport ledger disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_map_after_transport", "activate_transport_end_control");
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagEnd)) {
      FailScenario("\"transport back control is missing or cannot receive native input\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"transport back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"transport back navigation left an unexpected modal\"");
      return;
    }
    if (ScenarioPhaseTicks() < 20) {
      RequestScenarioTick();
      return;
    }
    Pass();
  }

  Phase phase;
};

TransportScreenTestCase g_test;

} // namespace

RuntimeTestCase* TransportScreenTest() {
  return &g_test;
}
