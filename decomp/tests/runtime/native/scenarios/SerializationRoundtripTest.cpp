#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/app/TAnimator.h"
#include "game/city_ui/TCountry.h"
#include "game/ArchiveStreamAdapter.h"
#include "game/core/TCountingStream.h"
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
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Serialization round-trip check.
//
// The save stream is flat and unframed, so the property that actually protects a load is
// that a class's reader consumes exactly the bytes its writer produced. `just serde-audit`
// proves that statically against the original's listing; this proves it dynamically
// against live game state, which additionally exercises the paths a static scan cannot
// see: length prefixes whose size depends on runtime data, collections whose element
// counts come from the objects themselves, and version gates evaluated for real.
//
// Per manager:
//   1. write into an in-memory CMemFile through a CArchive and a TFileStream -> N bytes
//   2. read the same object back from that buffer, then require the archive to be at
//      end-of-stream -- if one more byte can be read, the reader under-consumed
//   3. write a second time and compare buffers -> catches fields written but never read
//      back (and the reverse), without needing field-by-field equality on pointer-bearing
//      state
//
// It goes through CMemFile + CArchive + TFileStream rather than the simpler THandleStream
// on purpose. TStream's object slots (ReadObject 0xb0 / WriteObject 0xb4) are no-ops on
// the base class and THandleStream does not override them, so any class that serializes
// CObjects -- the trade manager's deal lists, the nation records' mission queues -- would
// write its element COUNT but none of the elements, and the read-back would then run off
// the end of the buffer and loop on garbage. THandleStream is the wrong instrument here;
// this is the same stack a real save uses, just backed by memory.
//
// Step 2 reads back into the SAME live object rather than a fresh one: these are
// singletons wired into the rest of the game and a second instance would neither
// construct nor destruct safely here.
//
// Scope note, and it matters: this validates our reader against OUR writer. It cannot
// prove fidelity to the retail format -- that is what serde-audit and the reccmp scores
// cover. A class can round-trip perfectly and still be wrong against a retail save. Both
// halves are needed; neither alone is sufficient.

namespace {

struct RoundtripTarget {
  const char* name;
  TObject* object;
  // Some ReadFrom bodies are not field readers at all: they tear down and rebuild global
  // state (TSimMgr frees and recreates every nation state, reloads asset gobs and
  // refreshes UI caches). Re-entering those on a live game corrupts it -- the real load
  // path only reaches them with the document machinery prepared for a load. Their write
  // side is still measured; only the read-back is skipped, with the reason recorded.
  bool readBackIsSafe;
  // Why a class legitimately fails the write -> read -> write stability check, or null
  // when it must be stable. Recorded rather than silently tolerated: an unexplained
  // instability is a finding, an explained one is the original's design.
  const char* expectedUnstable;
};

// Runs once the map exists, so the managers hold real state rather than default-constructed
// emptiness -- an empty collection round-trips trivially and would prove nothing. The whole
// check is synchronous, so the script has no waits: it is linear because it always was.
class SerializationRoundtripTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RunRoundtrips();
    if (failed != 0) {
      RT_FAIL(static_cast<LPCSTR>(FailureSummary()));
    }
    RT_PASS();
    RT_END();
  }

private:
  CString FailureSummary() const {
    CString text;
    text.Format("%d of %d serializers did not round-trip; see serialization_roundtrip in the "
                "result",
                failed, checked);
    return text;
  }

  CString report;
  int checked;
  int failed;

  void RunRoundtrips() {
    RoundtripTarget targets[] = {
        {"TAmbitApplication", g_pAmbitApplication, true, 0},
        {"TSimMgr", g_pSimMgr, false, 0},
        {"TAnimator", g_pUiAnimator, true, 0},
        {"TTradeMgr", g_pTradeMgr, true, 0},
        {"TDiplomacyMgr", g_pDiplomacyTurnStateManager, true, 0},
        {"TTechMgr", g_pTechMgr, true, 0},
        // WriteTo emits terrainStateTable and cityScoreTable as raw blocks, and those
        // records carry live pointers (firstCivilianOrder20 at +0x20 of a 0x24 record,
        // stationedUnitChain98 in the city record). ReadFrom deliberately nulls them
        // afterwards, so the second write cannot reproduce the first. That is the
        // original's design; the bytes are still accounted for, which is what matters.
        {"TMapMgr", g_pGlobalMapState, true,
         "WriteTo emits raw records containing live pointers that ReadFrom nulls"},
        {"TOcean", g_pActiveMapOrderContext, false, 0},
        {"TNavyMgr", g_pNavyOrderManager, true, 0},
        {"TArmyMgr", g_pMapContextActionManager, true, 0},
        {"TViewMgr", g_pViewMgr, true, 0},
        {"TMacViewMgr", g_pMacViewMgr, true, 0},
        {"TNewsMgr", g_pNewsMgr, true, 0},
        // indexList is a TSortedPtrList and its ReadFrom re-inserts each record through
        // the sort comparator without clearing first, so re-reading into an already
        // populated list can reorder it. Harmless on a real load, where the list is empty.
        {"THelpMgr", g_pHelpMgr, true,
         "sorted list re-inserts into an already populated container on re-read"},
    };
    const int targetCount = sizeof(targets) / sizeof(targets[0]);

    checked = 0;
    failed = 0;
    report = "[";

    // Pin the save-format version for the duration. Outside a load g_nSaveFormatVersion
    // is -1, and every version-gated reader then takes its oldest-format branch while the
    // writer always emits the current format -- which makes every gated class look like it
    // under-reads. DoRead sets this from the file header for exactly the same reason.
    const int savedFormatVersion = g_nSaveFormatVersion;
    g_nSaveFormatVersion = g_nCurrentAmbitSaveFormatVersion;

    for (int index = 0; index < targetCount; ++index) {
      CheckOne(targets[index].name, targets[index].object, targets[index].readBackIsSafe,
               targets[index].expectedUnstable);
    }

    // The nation records are read through a TCountry* loop in DoRead, so check the
    // concrete instances the same way the load path reaches them.
    for (short slot = 0; slot < kTerrainTypeDescriptorTableCount; ++slot) {
      TCountry* nation = g_apTerrainTypeDescriptorTable[slot];
      if (nation == 0) {
        continue;
      }
      CString label;
      label.Format("nation[%d]", slot);
      // Nation ReadFrom frees and recreates ministers and the city object.
      CheckOne(label, nation, false, 0);
    }

    g_nSaveFormatVersion = savedFormatVersion;
    report += "\n  ]";
    RecordSerializationRoundtripReport(report);
  }

  void CheckOne(const char* name, TObject* object, bool readBackIsSafe,
                const char* expectedUnstable) {
    ++checked;
    // Heartbeat per class: a hang inside one serializer would otherwise surface only as
    // "the scenario stopped responding", with no way to tell which one.
    MarkScriptStep(name);
    if (object == 0) {
      Record(name, "skipped", 0, 0, 0, "manager is null at map-ready time");
      return;
    }

    // 1. write through the real stack, into memory
    int written = 0;
    BYTE* first = WriteToMemory(object, written);
    if (written == 0) {
      // A genuinely empty serializer: TViewMgr, TMacViewMgr and TNewsMgr persist nothing
      // (their bodies are the original's, all 100%-matched). Nothing to round-trip, and
      // that is a pass, not a failure.
      Record(name, "passed", 0, 0, 0, "class persists no bytes");
      if (first != 0) {
        free(first);
      }
      return;
    }
    if (first == 0) {
      Record(name, "failed", written, 0, 0, "writer reported bytes but produced no buffer");
      ++failed;
      return;
    }

    if (!readBackIsSafe) {
      Record(name, "skipped", written, written, 0,
             "ReadFrom rebuilds global state; re-entering it on a live game is not safe "
             "(write side measured only)");
      free(first);
      return;
    }

    // 2. read it straight back and require the archive to be exhausted
    {
      CMemFile source(first, static_cast<UINT>(written));
      CArchive archive(&source, CArchive::load);
      ArchiveStreamAdapter adapter(&archive);
      TFileStream stream;
      stream.SetBackingArchive(&adapter);
      object->ReadFrom(&stream);
      unsigned char probe = 0;
      if (archive.Read(&probe, 1) != 0) {
        Record(name, "failed", written, written, 0,
               "reader left bytes unread: the writer produced more than the reader consumes");
        ++failed;
        free(first);
        return;
      }
    }

    // 3. write again and compare; equal lengths can still hide a field that is written
    //    but never read back, which comes out different the second time round.
    int rewritten = 0;
    BYTE* second = WriteToMemory(object, rewritten);
    if (second == 0) {
      Record(name, "failed", written, written, 0, "second write produced no bytes");
      ++failed;
      free(first);
      return;
    }

    if (rewritten != written) {
      Record(name, "failed", written, rewritten, written,
             "write -> read -> write changed the length");
      ++failed;
    } else if (memcmp(first, second, static_cast<size_t>(written)) != 0) {
      if (expectedUnstable != 0) {
        Record(name, "unstable_expected", written, rewritten, written, expectedUnstable);
      } else {
        Record(name, "failed", written, rewritten, written,
               "write -> read -> write is not stable; a field is written but not read back");
        ++failed;
      }
    } else {
      Record(name, "passed", written, rewritten, written, 0);
    }
    free(second);
    free(first);
  }

  // Serialize through CMemFile + CArchive + TFileStream -- the same stack a real save
  // uses, so CObject members serialize for real. Returns the detached buffer (the caller
  // frees it) and its length.
  BYTE* WriteToMemory(TObject* object, int& length) {
    CMemFile file;
    {
      CArchive archive(&file, CArchive::store);
      ArchiveStreamAdapter adapter(&archive);
      TFileStream stream;
      stream.SetBackingArchive(&adapter);
      object->WriteTo(&stream);
      archive.Close();
    }
    length = static_cast<int>(file.GetLength());
    if (length <= 0) {
      return 0;
    }
    return file.Detach();
  }

  void Record(const char* name, const char* status, int measured, int written, int consumed,
              const char* detail) {
    CString entry;
    CString detailJson("null");
    if (detail != 0) {
      detailJson.Format("\"%s\"", detail);
    }
    entry.Format("\n    {\"class\": \"%s\", \"status\": \"%s\", \"measured\": %d, "
                 "\"written\": %d, \"consumed\": %d, \"detail\": %s}",
                 name, status, measured, written, consumed, static_cast<LPCSTR>(detailJson));
    if (report.GetLength() > 1) {
      report += ",";
    }
    report += entry;
  }
};

} // namespace

RUNTIME_TEST_FACTORY(SerializationRoundtripTestCase, SerializationRoundtripTest)
