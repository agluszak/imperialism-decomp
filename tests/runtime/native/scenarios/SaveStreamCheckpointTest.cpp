#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/ArchiveStreamAdapter.h"
#include "game/assets/TAssetMgr.h"
#include "game/app/TAnimator.h"
#include "game/city_ui/TCountry.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TFileStream.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/map/TMapMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_map.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// Save-stream checkpoint oracle.
//
// It replays a save through the manager chain and records the byte offset either side of
// every ReadFrom. The first manager whose span does not end where the next one's begins
// is named outright instead of inferred, and if the final offset equals the file length
// the whole chain's accounting is proved end to end. That is what turns "the load crashed
// somewhere downstream" into "manager N consumed the wrong number of bytes".
//
// It replays a save this build just WROTE, not a committed fixture. The fixture that used
// to back this test was itself produced by an older build of ours and was stale, which
// made a correct reader look broken (imperialism-decomp-cinw.17) -- a save whose
// provenance cannot be checked in is worse than no save at all. Self-saving costs the
// retail-fidelity half of the question and keeps the reader-vs-writer half, which is the
// half that finds desyncs; pointing this at a genuine retail save is strictly stronger and
// is what load_saved_game is for.
//
// It deliberately reimplements the DoRead sequence here rather than instrumenting
// TAmbitFileBasedDocument::DoRead (0x49e6a0). Adding checkpoint calls to a production
// body would change its codegen and its reccmp score for the sake of a test; the header
// layout and manager order are small, fixed, and asserted against DoRead by the comment
// below, so the duplication is cheap and the production tree stays untouched.
//
// KEEP IN SYNC with TAmbitFileBasedDocument::DoRead. If a manager is added, removed or
// reordered there, this list must follow, or the oracle will report a phantom desync.

namespace {

// CArchive buffers ahead of its caller and keeps the buffer cursor protected, so the
// file's own offset is not the logical read position. Count what the managers actually
// consume instead: every typed accessor on TStream funnels through the ReadBytes
// primitive (slot 0x3c), so overriding that one method sees every byte.
//
// The exception is ReadObject (slot 0xb0), which TFileStream forwards straight to
// CArchive::ReadObject without going through ReadBytes. Spans containing one are marked
// approximate rather than silently wrong -- in this chain that is the nation records,
// whose mission-node queues read objects.
class CountingFileStream : public TFileStream {
public:
  CountingFileStream() : consumed(0), objectReads(0) {}

  void ReadBytes(void* destination, int requestedCount) override {
    TFileStream::ReadBytes(destination, requestedCount);
    consumed += requestedCount;
  }

  char ReadObject(void* outObject) override {
    ++objectReads;
    return TFileStream::ReadObject(outObject);
  }

  int consumed;
  int objectReads;
};

// Replays only once a game exists. TSimMgr::ReadFrom rebuilds the nation states through
// TMapMgr::ChooseNationSetupProfilesForOpenSlots, which reads live map tables -- at
// manager-ready time there is no map and it dereferences null. The real load path has the same
// requirement; the document machinery satisfies it before Serialize runs.
//
// The replay is synchronous, so the script has no waits. Failures are reported through
// `failure`, which Replay sets, because the steps that can fail are nested helpers rather than
// script statements.
class SaveStreamCheckpointTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    Replay();
    if (!failure.IsEmpty()) {
      RT_FAIL(static_cast<LPCSTR>(failure));
    }
    RT_PASS();
    RT_END();
  }

private:
  CString report;
  CString failure;
  int entries;

  void Replay() {
    report = "[";
    failure.Empty();
    entries = 0;

    // Enter the replay from the state a real load is entered from. A load reached from the menu has
    // no units linked into the map; this replay runs on top of a played game, and
    // TSimMgr::ReadFrom's rebuild frees every nation's units without unlinking them from
    // cityScoreTable[P].stationedUnitChain98 (TUnit::Free, verified faithful at 0x5c2680, does not
    // unlink; nor does TCountry::Free at 0x4d6ba0). The freshly seeded units are then linked in
    // front of those freed ones, and walking that tail is imperialism-decomp-srql. Detaching first,
    // through each unit's own DetachUnitOrderFromOwnerAndReset, removes the difference between this
    // replay and a menu load rather than papering over what the rebuild does.
    DetachLiveMilitaryUnitsFromMap();

    // Write the save first, through the same document path a real save uses, so the
    // bytes being replayed are this build's own and their provenance is beyond doubt.
    CString path("save/rt_save_stream_checkpoints.imp");
    if (g_pAssetMgr->SaveMainDocumentToPathAndMarkSaved(path) == 0) {
      FailScenario("\"the document refused to save through the real save path\"");
      return;
    }

    CFile file;
    CFileException error;
    if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite, &error)) {
      FailScenario("\"could not reopen the just-written save for checkpoint replay\"");
      return;
    }
    const int fileLength = static_cast<int>(file.GetLength());

    CArchive archive(&file, CArchive::load);
    ArchiveStreamAdapter adapter(&archive);
    CountingFileStream stream;
    stream.SetBackingArchive(&adapter);

    // Header, exactly as DoRead consumes it.
    int fileMagic = 0;
    int savedSessionSlot = 0;
    char label[0x20];
    stream.ReadBytes(&fileMagic, 4);
    stream.ReadBytes(&g_nSaveFormatVersion, 4);
    stream.ReadBytes(&savedSessionSlot, 4);
    stream.ReadBytes(label, 0x20);
    if (fileMagic != kControlTagAMBI) {
      g_nSaveFormatVersion = -1;
      FailScenario("\"save fixture does not start with the AMBI magic\"");
      return;
    }
    unsigned char discarded[0x1950];
    stream.ReadBytes(discarded, 0x1950);
    stream.ReadBytes(discarded, 0x24);
    Record("header", 0, stream.consumed, 0);

    struct ChainEntry {
      const char* name;
      TObject* object;
    };
    ChainEntry chain[] = {
        {"TAmbitApplication", g_pAmbitApplication},
        {"TSimMgr", g_pSimMgr},
        {"TAnimator", g_pUiAnimator},
        {"TTradeMgr", g_pTradeMgr},
        {"TDiplomacyMgr", g_pDiplomacyTurnStateManager},
        {"TTechMgr", g_pTechMgr},
        {"TMapMgr", g_pGlobalMapState},
        {"TOcean", g_pActiveMapOrderContext},
        {"TNavyMgr", g_pNavyOrderManager},
        {"TArmyMgr", g_pMapContextActionManager},
    };
    const int chainCount = sizeof(chain) / sizeof(chain[0]);

    for (int index = 0; index < chainCount; ++index) {
      if (!ReadOne(stream, chain[index].name, chain[index].object)) {
        return;
      }
    }

    for (short slot = 0; slot < kTerrainTypeDescriptorTableCount; ++slot) {
      if (g_apTerrainTypeDescriptorTable[slot] == 0) {
        continue;
      }
      CString label2;
      label2.Format("nation[%d]", slot);
      if (!ReadOne(stream, label2, g_apTerrainTypeDescriptorTable[slot])) {
        return;
      }
    }

    ChainEntry tail[] = {
        {"TViewMgr", g_pViewMgr},
        {"TMacViewMgr", g_pMacViewMgr},
        {"TNewsMgr", g_pNewsMgr},
        {"THelpMgr", g_pHelpMgr},
    };
    // VC5 leaks a for-scoped declaration into the enclosing block, so this loop needs
    // its own name rather than reusing `index`.
    for (int tailIndex = 0; tailIndex < 4; ++tailIndex) {
      if (!ReadOne(stream, tail[tailIndex].name, tail[tailIndex].object)) {
        return;
      }
    }

    // The decisive whole-chain assertion, and the one immune to buffering: if the chain
    // consumed the file exactly, one more byte cannot be read.
    unsigned char probe = 0;
    const UINT leftover = archive.Read(&probe, 1);
    report += "\n  ]";
    RecordSerializationRoundtripReport(report);
    g_nSaveFormatVersion = -1;

    if (leftover != 0) {
      failure.Format("the manager chain left bytes unread (counted %d consumed of a %d byte "
                     "file); compare each span in save_stream_checkpoints against the same "
                     "class in serialization_roundtrip -- the first span whose size disagrees "
                     "names the divergent manager",
                     stream.consumed, fileLength);
    }
  }

  // Reading into the live managers is what the real load does; a checkpoint replay that
  // read into throwaway objects would not exercise the same version gates or collection
  // states. The game state after this test is spent, which is why nothing follows it.
  void DetachLiveMilitaryUnitsFromMap() {
    for (short slot = 0; slot < kTerrainTypeDescriptorTableCount; ++slot) {
      TCountry* country = g_apTerrainTypeDescriptorTable[slot];
      TSortedList* units = country != 0 ? country->militaryUnitList44 : 0;
      if (units == 0) {
        continue;
      }
      // Walk by ordinal and detach in place: the list keeps its payloads, only the map chains let go.
      for (int ordinal = 1; ordinal <= units->GetCount(); ++ordinal) {
        CObject* entry = static_cast<CObject*>(units->GetEntryByOrdinal(ordinal));
        if (entry != 0 && entry->IsKindOf(RUNTIME_CLASS(TMilitaryUnit)) != 0) {
          static_cast<TMilitaryUnit*>(entry)->DetachUnitOrderFromOwnerAndReset();
        }
      }
    }
  }

  bool ReadOne(CountingFileStream& stream, const char* name, TObject* object) {
    if (object == 0) {
      failure.Format("%s is null before its ReadFrom; the chain cannot be replayed", name);
      report += "\n  ]";
      RecordSerializationRoundtripReport(report);
      g_nSaveFormatVersion = -1;
      return false;
    }
    const int before = stream.consumed;
    const int objectsBefore = stream.objectReads;
    object->ReadFrom(&stream);
    Record(name, before, stream.consumed, stream.objectReads - objectsBefore);
    return true;
  }

  void Record(const char* name, int before, int after, int objectReads) {
    CString entry;
    entry.Format("\n    {\"span\": \"%s\", \"from\": %d, \"to\": %d, \"bytes\": %d, "
                 "\"object_reads\": %d, \"exact\": %s}",
                 name, before, after, after - before, objectReads,
                 objectReads == 0 ? "true" : "false");
    if (entries != 0) {
      report += ",";
    }
    report += entry;
    ++entries;
  }
};

} // namespace

RUNTIME_TEST_FACTORY(SaveStreamCheckpointTestCase, SaveStreamCheckpointTest)
