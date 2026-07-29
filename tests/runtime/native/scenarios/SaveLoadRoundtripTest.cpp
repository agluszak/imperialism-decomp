#include "RuntimeScenario.h"
#include "RuntimeUiDriver.h"
#include "flows/RandomGameFlow.h"

#include "game/assets/TAssetMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_tags_map.h"
#include "game/globals/view_registries.h"
#include "game/turn_event_codes.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

// Save then load, both through the real document path.
//
// This is the end-to-end test the serialization epic was built toward, and the only one
// that exercises DoWrite and DoRead against each other the way the game does:
// TAssetMgr::SaveMainDocumentToPathAndMarkSaved -> CDocument::OnSaveDocument ->
// CAmbitDocument::Serialize -> DoWrite, and then the mirror through OpenDocumentFile.
//
// It needs no committed fixture, which matters: load_saved_game depends on a gitignored
// local save whose provenance cannot be checked in, and a stale one produced by an older
// build reads as a port defect when it is nothing of the kind. This test carries its own
// data by construction.
//
// What it proves and what it does not: passing means our writer and reader agree through
// the real document machinery, on real game state, including every version gate and the
// CObject sub-format. It does NOT prove fidelity to a retail save -- only a genuine
// retail-produced file does that, which is what load_saved_game is for.

namespace {

class SaveLoadRoundtripTestCase : public RandomGameScenario {
public:
  SaveLoadRoundtripTestCase() : phase(kOpenSaveDialog), savedTurn(0), savedNation(0) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    if (phase != kOpenSaveDialog) {
      return;
    }
    savedTurn = g_pSimMgr->economicTurn;
    savedNation = g_pSimMgr->activeNationSlot;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventLoadSave), savedNation);
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TLoadSavePicture)) == 0) {
      FailScenario("\"load-save event did not construct TLoadSavePicture\"");
      return;
    }
    phase = kSelectSaveSlot;
    EnterScenarioStep("selecting_save_slot", "open_real_save_dialog");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kSelectSaveSlot) {
      SelectSlotAndSaveThroughDialog();
    } else if (phase == kWaitForSaveFlowTransition) {
      WaitForSaveFlowTransition();
    } else {
      WaitForLoadedMap();
    }
  }

private:
  enum Phase { kOpenSaveDialog, kSelectSaveSlot, kWaitForSaveFlowTransition, kWaitForLoadedMap };

  Phase phase;
  int savedTurn;
  short savedNation;
  CString savedPath;

  void SelectSlotAndSaveThroughDialog() {
    if (g_pSimMgr == 0 || g_pGlobalMapState == 0) {
      FailScenario("\"managers are not live at map-ready time\"");
      return;
    }
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TLoadSavePicture)) == 0) {
      FailScenario("\"save dialog disappeared before slot selection\"");
      return;
    }
    TLoadSavePicture* savePicture = static_cast<TLoadSavePicture*>(mainView);
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(savePicture, kControlTagSlt0) ||
        savePicture->selectedSlot92 != 0) {
      FailScenario("\"native save-slot click did not select slot zero\"");
      return;
    }
    TView* slotEditor = savePicture->ResolveControlByTag(kControlTagSlot);
    if (slotEditor == 0 || slotEditor->IsKindOf(RUNTIME_CLASS(TEditText)) == 0) {
      FailScenario("\"selected save slot did not enter the retail name-editing state\"");
      return;
    }
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(savePicture, kControlTagOkay)) {
      FailScenario("\"save dialog okay control did not accept the selected slot\"");
      return;
    }

    CString path;
    BuildSavePathStringForMode(&path, 0, 0);
    if (TryGetFileMetadataForPath(&path) == 0) {
      FailScenario("\"selected save slot did not write through the retail save flow\"");
      return;
    }
    ReportSavedFileShape(path);
    savedPath = path;
    phase = kWaitForSaveFlowTransition;
    EnterScenarioStep("waiting_for_save_flow_transition", "selected_slot_saved_through_dialog");
    RequestScenarioTick();
  }

  void WaitForSaveFlowTransition() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode == EncodeTurnEventCode(kTurnEventLoadSave) ||
        (mainView != 0 && mainView->IsKindOf(RUNTIME_CLASS(TLoadSavePicture)) != 0)) {
      WaitForScenarioTick("\"the save dialog did not advance through the retail turn flow\"");
      return;
    }
    if (g_pAssetMgr->OpenMainDocumentFromPathAndMarkLoaded(savedPath) == 0) {
      FailScenario("\"the just-written save would not open through the real load path\"");
      return;
    }

    phase = kWaitForLoadedMap;
    EnterScenarioStep("waiting_for_loaded_map", "selected_slot_saved_and_reopened");
    RequestScenarioTick();
  }

  // Header + length only: cheap, and enough to separate "the writer produced nonsense"
  // from "the reader mis-consumed sane bytes".
  void ReportSavedFileShape(const CString& path) {
    CString report("[");
    CFile file;
    CFileException error;
    if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite, &error)) {
      report += "\n    {\"saved_file\": \"unreadable\"}\n  ]";
      RecordSerializationRoundtripReport(report);
      return;
    }
    const int fileLength = static_cast<int>(file.GetLength());
    int header[3];
    header[0] = 0;
    header[1] = 0;
    header[2] = 0;
    file.Read(header, sizeof(header));
    int liveNations = 0;
    for (short slot = 0; slot < kTerrainTypeDescriptorTableCount; ++slot) {
      if (g_apTerrainTypeDescriptorTable[slot] != 0) {
        ++liveNations;
      }
    }
    CString entry;
    entry.Format("\n    {\"saved_file\": \"written\", \"bytes\": %d, \"magic_ok\": %s, "
                 "\"format_version\": %d, \"live_nation_records\": %d}\n  ]",
                 fileLength, header[0] == kControlTagAMBI ? "true" : "false", header[1],
                 liveNations);
    report += entry;
    RecordSerializationRoundtripReport(report);
  }

  void WaitForLoadedMap() {
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != 0x7dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"the reloaded game did not reach the combined strategic map\"");
      return;
    }
    if (g_pGlobalMapState == 0) {
      FailScenario("\"the reloaded game has no global map state\"");
      return;
    }
    if (g_pSimMgr->activeNationSlot != savedNation) {
      FailScenario("\"the reloaded game has a different active nation than the saved one\"");
      return;
    }
    if (g_pSimMgr->economicTurn != savedTurn) {
      FailScenario("\"the reloaded game is on a different economic turn than the saved one\"");
      return;
    }
    SetSelectedNation(g_pSimMgr->activeNationSlot);
    Pass();
  }
};

SaveLoadRoundtripTestCase g_test;

} // namespace

RuntimeTestCase* SaveLoadRoundtripTest() {
  return &g_test;
}
