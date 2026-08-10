#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "probes/UnitChainProbe.h"
#include "screens/LoadSaveScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/assets/TAssetMgr.h"
#include "game/city/TCity.h"
#include "game/city/TShipOrder.h"
#include "game/globals/assets_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/nation_globals.h"
#include "game/map/TMapMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/nation/TGreatPower.h"
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
const short kFirstNavyShipyardRow = 4;
const int kPatrolOrder = 3;

bool CapturePersistentGameState(const RuntimeRun& run, CString& persistentState) {
  JSON_Value* value = 0;
  if (!BuildRuntimeGameState(run, &value)) {
    return false;
  }
  JSON_Object* state = json_value_get_object(value);
  JSON_Object* nations = state != 0 ? json_object_get_object(state, "nations") : 0;
  JSON_Array* majors = nations != 0 ? json_object_get_array(nations, "majors") : 0;
  if (state == 0 || json_object_remove(state, "turn") != JSONSuccess ||
      json_object_remove(state, "unit_ids") != JSONSuccess ||
      json_object_remove(state, "rng") != JSONSuccess || majors == 0) {
    json_value_free(value);
    return false;
  }
  // TAutoGreatPower::WriteTo/ReadFrom omit these fort-scoring caches. Loading reconstructs the AI
  // object without initializing them; phase 0x15 recomputes them later. Keep exact bits in
  // complete-state differentials while excluding them from this persistence-only comparison.
  for (size_t index = 0; index < json_array_get_count(majors); ++index) {
    JSON_Object* major = json_array_get_object(majors, index);
    JSON_Object* economy = major != 0 ? json_object_get_object(major, "economy") : 0;
    if (economy == 0 || json_object_remove(economy, "ai_development_pressure") != JSONSuccess) {
      json_value_free(value);
      return false;
    }
  }
  char* serialized = json_serialize_to_string(value);
  json_value_free(value);
  if (serialized == 0) {
    return false;
  }
  persistentState = serialized;
  json_free_serialized_string(serialized);
  return true;
}

CString DescribeGameStateDifference(const CString& before, const CString& after) {
  int sharedLength = before.GetLength();
  if (after.GetLength() < sharedLength) {
    sharedLength = after.GetLength();
  }
  int difference = 0;
  while (difference < sharedLength && before[difference] == after[difference]) {
    ++difference;
  }
  const int contextStart = difference > 60 ? difference - 60 : 0;
  CString message;
  message.Format("persistent game state differs at byte %d; before: %.160s; after: %.160s",
                 difference, static_cast<LPCSTR>(before.Mid(contextStart)),
                 static_cast<LPCSTR>(after.Mid(contextStart)));
  return message;
}

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
    RT_REQUIRE(CreatePersistedNavyState());
    RT_REQUIRE(CapturePersistentGameState(RunState(), beforePersistentState));

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
    RT_REQUIRE(CapturePersistentGameState(RunState(), afterPersistentState));
    if (beforePersistentState != afterPersistentState) {
      stateDifference = DescribeGameStateDifference(beforePersistentState, afterPersistentState);
      RT_FAIL(stateDifference);
    }
    RT_PASS();

    RT_END();
  }

private:
  bool CreatePersistedNavyState() {
    TGreatPower* player = g_apNationStates[savedNation];
    TCity* city = player != 0 ? player->city : 0;
    TShipOrder* order = city != 0 ? city->shipOrderSlots190[kFirstNavyShipyardRow] : 0;
    if (order == 0) {
      return false;
    }

    // A fresh random game need not stock every input for this hull. Supply exactly one hull's
    // retail costs, then use the ordinary SetQuantity/Produce path so the save fixture contains
    // state created by the game rather than a hand-built TShip or TTaskForce.
    const short type = order->resourceTypeIndex;
    city->cityStockLumberC8 = g_industryActionCostWeightResCode09[type];
    city->cityStockFabricC6 = g_industryActionCostWeightResCode08[type];
    city->cityStockArmsD6 = g_industryActionCostWeightResCode10[type];
    city->cityStockSteelCC = g_industryActionCostWeightResCode0B[type];
    city->cityStockCoalBC = g_industryActionCostWeightResCode03[type];
    city->cityStockFuelCE = g_industryActionCostWeightResCode0C[type];
    if (!order->SetQuantity(1)) {
      return false;
    }

    TShip* priorHead = g_pNavyPrimaryOrderListHead;
    order->Produce();
    TShip* ship = g_pNavyPrimaryOrderListHead;
    if (ship == 0 || ship == priorHead || ship->nation != savedNation) {
      return false;
    }

    TTaskForce* force = ship->DemandExclusiveTaskForce();
    if (force == 0) {
      return false;
    }
    force->SubmitOrders(kPatrolOrder, 0);
    return g_pNavyOrderManager != 0 && g_pNavyOrderManager->orderQueueHead == force &&
           ship->taskForce == force;
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
    JSON_Value* value = json_value_init_object();
    JSON_Object* report = value != 0 ? json_value_get_object(value) : 0;
    if (report == 0) {
      json_value_free(value);
      return;
    }
    CFile file;
    CFileException error;
    if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite, &error)) {
      if (json_object_set_string(report, "saved_file", "unreadable") != JSONSuccess) {
        json_value_free(value);
        return;
      }
      RecordSerializationRoundtripReport(value);
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
    if (json_object_set_string(report, "saved_file", "written") != JSONSuccess ||
        json_object_set_number(report, "bytes", fileLength) != JSONSuccess ||
        json_object_set_boolean(report, "magic_ok", header[0] == kControlTagAMBI) != JSONSuccess ||
        json_object_set_number(report, "format_version", header[1]) != JSONSuccess ||
        json_object_set_number(report, "live_nation_records", liveNations) != JSONSuccess) {
      json_value_free(value);
      return;
    }
    RecordSerializationRoundtripReport(value);
  }

  int savedTurn;
  short savedNation;
  int savedTurnState;
  int savedDifficulty;
  int savedScenarioMap;
  CString savedPath;
  CString beforePersistentState;
  CString afterPersistentState;
  CString stateDifference;
};

} // namespace

RUNTIME_TEST_FACTORY(SaveLoadRoundtripTestCase, SaveLoadRoundtripTest)
