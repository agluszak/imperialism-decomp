#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameSnapshot.h"
#include "probes/UnitChainProbe.h"
#include "screens/LoadSaveScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/assets/TAssetMgr.h"
#include "game/globals/assets_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/nation_globals.h"
#include "game/map/TMapMgr.h"
#include "game/nation_domain_types.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

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

// The slot this scenario saves into, and the save mode that names its file.
const short kSaveSlot = 0;
const int kNormalSaveMode = 0;

class SaveLoadRoundtripTestCase : public EasyMapScriptScenario {
public:
  SaveLoadRoundtripTestCase()
      : savedTurn(0), savedNation(0), savedTurnState(0), savedDifficulty(0), savedScenarioMap(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    savedTurn = g_pSimMgr->economicTurn;
    savedNation = g_pSimMgr->activeNationSlot;
    savedTurnState = g_pSimMgr->turnStateCode;
    savedDifficulty = g_pSimMgr->difficultyLevel;
    savedScenarioMap = g_pSimMgr->scenarioMapIndexPlusOne;
    SetSelectedNation(savedNation);
    RT_REQUIRE(BuildRuntimeGameSnapshot(RunState(), beforeSaveSnapshot));
    beforePersistentState = PersistentSnapshotState(beforeSaveSnapshot);

    RT_DO("open the save dialog", LoadSaveScreen::OpenForNation(savedNation));
    RT_REQUIRE(LoadSaveScreen::IsCurrent());

    RT_DO("select the first save slot", LoadSave().SelectSlot(kSaveSlot));
    RT_REQUIRE_EQ(kSaveSlot, LoadSave().SelectedSlot());
    RT_REQUIRE(LoadSave().SlotIsBeingNamed());

    // Okay writes through the document path synchronously, so the file is there to inspect by the
    // time this returns.
    RT_DO("accept the selected slot", LoadSave().Accept());
    BuildSavePathStringForMode(&savedPath, kNormalSaveMode, 0);
    RT_REQUIRE(TryGetFileMetadataForPath(&savedPath) != 0);
    ReportSavedFileShape(savedPath);

    // The retail save flow leaves this screen by itself.
    RT_AWAIT(LoadSaveScreen::IsDismissed(), kObserveUiStateChanged);
    RT_DO("reopen the saved game through the real load path", ReopenSavedGame());

    while (!StrategicMapScreen::IsCurrent()) {
      if (NewspaperScreen::IsCurrent() && Newspaper().EndControlIsReady()) {
        RT_DO("close the newspaper", Newspaper().Close());
      } else {
        RT_AWAIT(StrategicMapScreen::IsCurrent() ||
                     (NewspaperScreen::IsCurrent() && Newspaper().EndControlIsReady()),
                 kObserveUiStateChanged);
      }
    }

    RT_REQUIRE_NOT_NULL(g_pGlobalMapState);
    // A load rebuilds the world under the units the live game already had, and re-threads the map's
    // unit chains as it goes. A chain left holding a non-pointer survives silently until something
    // walks it, and then it is a page fault inside TMilitaryUnit::MoveTo with no context
    // (imperialism-decomp-ilfs) -- so the reloaded game is held to walkable chains here, where the
    // invariant is unambiguous.
    RT_DO("confirm the reloaded map's unit chains",
          UnitChainProbe::VerifyChainsAreWalkable("the reload"));
    RT_REQUIRE_EQ(savedNation, g_pSimMgr->activeNationSlot);
    RT_REQUIRE_EQ(savedTurn, g_pSimMgr->economicTurn);
    RT_REQUIRE_EQ(savedTurnState, g_pSimMgr->turnStateCode);
    RT_REQUIRE_EQ(savedDifficulty, g_pSimMgr->difficultyLevel);
    RT_REQUIRE_EQ(savedScenarioMap, g_pSimMgr->scenarioMapIndexPlusOne);
    SetSelectedNation(g_pSimMgr->activeNationSlot);
    RT_REQUIRE(BuildRuntimeGameSnapshot(RunState(), afterLoadSnapshot));
    afterPersistentState = PersistentSnapshotState(afterLoadSnapshot);
    if (beforePersistentState != afterPersistentState) {
      snapshotDifference = DescribeSnapshotDifference(beforePersistentState, afterPersistentState);
      RT_FAIL(snapshotDifference);
    }
    RT_PASS();

    RT_END();
  }

private:
  CString PersistentSnapshotState(const CString& snapshot) {
    int stateIndex = snapshot.Find("\"world\":{");
    return stateIndex < 0 ? CString() : snapshot.Mid(stateIndex);
  }

  CString DescribeSnapshotDifference(const CString& before, const CString& after) {
    const char* bodyMarker = "\"world\":{";
    int beforeIndex = before.Find(bodyMarker);
    int afterIndex = after.Find(bodyMarker);
    if (beforeIndex < 0 || afterIndex < 0) {
      return CString("game snapshot has no persistent world section");
    }
    int sharedLength = before.GetLength() - beforeIndex;
    if (after.GetLength() - afterIndex < sharedLength) {
      sharedLength = after.GetLength() - afterIndex;
    }
    int difference = 0;
    while (difference < sharedLength &&
           before[beforeIndex + difference] == after[afterIndex + difference]) {
      ++difference;
    }
    int contextStart = difference > 60 ? difference - 60 : 0;
    CString message;
    message.Format("canonical game state differs at byte %d; before: %.160s; after: %.160s",
                   difference, static_cast<LPCSTR>(before.Mid(beforeIndex + contextStart)),
                   static_cast<LPCSTR>(after.Mid(afterIndex + contextStart)));
    return message;
  }

  RuntimeActionResult ReopenSavedGame() {
    if (g_pAssetMgr->OpenMainDocumentFromPathAndMarkLoaded(savedPath) == 0) {
      return RuntimeActionResult::Failure(
          "the just-written save would not open through the real load path");
    }
    return RuntimeActionResult::Success();
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
    for (short slot = 0; slot < kNationSlotCount; ++slot) {
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

  int savedTurn;
  short savedNation;
  int savedTurnState;
  int savedDifficulty;
  int savedScenarioMap;
  CString savedPath;
  CString beforeSaveSnapshot;
  CString afterLoadSnapshot;
  CString beforePersistentState;
  CString afterPersistentState;
  CString snapshotDifference;
};

} // namespace

RUNTIME_TEST_FACTORY(SaveLoadRoundtripTestCase, SaveLoadRoundtripTest)
