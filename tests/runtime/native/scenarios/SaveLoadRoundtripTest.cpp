#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"

#include "game/assets/TAssetMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_tags_map.h"

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
  SaveLoadRoundtripTestCase() : phase(kSave), savedTurn(0), savedNation(0) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    if (phase != kSave) {
      return;
    }
    EnterScenarioStep("saving_game", "save_main_document");
    SaveAndReload();
  }

  void TickScenario() override {
    WaitForLoadedMap();
  }

private:
  enum Phase { kSave, kWaitForLoadedMap };

  Phase phase;
  int savedTurn;
  short savedNation;

  void SaveAndReload() {
    if (g_pSimMgr == 0 || g_pGlobalMapState == 0) {
      FailScenario("\"managers are not live at map-ready time\"");
      return;
    }
    // Remember enough to prove the reload restored the same game rather than starting a
    // fresh one -- a load that silently fell back to a new game would otherwise pass.
    savedTurn = g_pSimMgr->economicTurn;
    savedNation = g_pSimMgr->activeNationSlot;

    CString path("save/rt_save_load_roundtrip.imp");
    if (g_pUiViewManager->SaveMainDocumentToPathAndMarkSaved(path) == 0) {
      FailScenario("\"the document refused to save through the real save path\"");
      return;
    }

    // Before handing the file to the document machinery, record how many bytes the
    // writer actually produced and whether the header is well formed. If the load below
    // faults while these numbers are sane, the fault is in the load path's state rebuild
    // rather than in the byte stream -- save_stream_checkpoints proves the chain's
    // accounting separately, and this pins the two halves to the same file.
    ReportSavedFileShape(path);

    if (g_pUiViewManager->OpenMainDocumentFromPathAndMarkLoaded(path) == 0) {
      FailScenario("\"the just-written save would not open through the real load path\"");
      return;
    }

    phase = kWaitForLoadedMap;
    EnterScenarioStep("waiting_for_loaded_map", "opened_saved_game");
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
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x7dd || mainView == 0 ||
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
