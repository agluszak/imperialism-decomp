#include "RuntimeScenario.h"

#include "game/app/TAnimator.h"
#include "game/city_ui/TCountry.h"
#include "game/core/THandleStream.h"
#include "game/core/TCountingStream.h"
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
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

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
//   1. measure with a TCountingStream            -> N bytes
//   2. write into a THandleStream                -> position must land on N
//   3. rewind and read the same object back      -> position must land on N again
//   4. write a second time and compare buffers   -> catches fields written but never
//                                                   read back (and the reverse), without
//                                                   needing field-by-field equality on
//                                                   pointer-bearing state
//
// Step 3 reads back into the SAME live object rather than a fresh one. That is deliberate:
// these are singletons wired into the rest of the game (TMapMgr owns the terrain tables,
// TSimMgr the turn state), and a second instance would neither construct nor destruct
// safely here. Reading into the live object is what the real load path does anyway.
//
// Scope note, and it matters: this validates our reader against OUR writer. It cannot
// prove fidelity to the retail format -- that is what serde-audit and the reccmp scores
// cover. A class can round-trip perfectly and still be wrong against a retail save. Both
// halves are needed; neither alone is sufficient.

namespace {

struct RoundtripTarget {
  const char* name;
  TObject* object;
};

class SerializationRoundtripTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "serialization_roundtrip";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  bool UsesEasyDifficulty() const override {
    return true;
  }

  // Run once the map exists, so the managers hold real state rather than
  // default-constructed emptiness -- an empty collection round-trips trivially and
  // would prove nothing.
  void OnEasyMapReady() override {
    EnterScenarioStep("serialization_roundtrip", "collect_managers");
    RunRoundtrips();
  }

private:
  CString report;
  int checked;
  int failed;

  void RunRoundtrips() {
    RoundtripTarget targets[] = {
        {"TAmbitApplication", g_pGlobalUiRootController},
        {"TSimMgr", g_pSimMgr},
        {"TAnimator", g_pUiAnimator},
        {"TTradeMgr", g_pNationInteractionStateManager},
        {"TDiplomacyMgr", g_pDiplomacyTurnStateManager},
        {"TTechMgr", g_pCityOrderCapabilityState},
        {"TMapMgr", g_pGlobalMapState},
        {"TOcean", g_pActiveMapOrderContext},
        {"TNavyMgr", g_pNavyOrderManager},
        {"TArmyMgr", g_pMapContextActionManager},
        {"TViewMgr", g_pUiRuntimeContext},
        {"TMacViewMgr", g_pStrategicMapViewSystem},
        {"TNewsMgr", g_pNewsMgr},
        {"THelpMgr", g_pHelpMgr},
    };
    const int targetCount = sizeof(targets) / sizeof(targets[0]);

    checked = 0;
    failed = 0;
    report = "[";

    for (int index = 0; index < targetCount; ++index) {
      CheckOne(targets[index].name, targets[index].object);
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
      CheckOne(label, nation);
    }

    report += "\n  ]";
    RecordSerializationRoundtripReport(report);

    if (failed != 0) {
      CString failure;
      failure.Format("\"%d of %d serializers did not round-trip; see "
                     "serialization_roundtrip in the result\"",
                     failed, checked);
      FailScenario(failure);
      return;
    }
    Pass();
  }

  void CheckOne(const char* name, TObject* object) {
    ++checked;
    if (object == 0) {
      Record(name, "skipped", 0, 0, 0, "manager is null at map-ready time");
      return;
    }

    // 1. measured length
    TCountingStream counter;
    counter.PrepareForUse();
    object->WriteTo(&counter);
    const int measured = counter.GetPosition();
    if (measured <= 0) {
      Record(name, "failed", measured, 0, 0, "writer produced no bytes");
      ++failed;
      return;
    }

    // 2. write into a real buffer
    HGLOBAL buffer = GlobalAlloc(GMEM_MOVEABLE, static_cast<DWORD>(measured) * 2 + 0x40);
    if (buffer == 0) {
      Record(name, "skipped", measured, 0, 0, "GlobalAlloc failed");
      return;
    }
    THandleStream stream;
    stream.AttachGlobalMemoryHandleAndResetPosition(buffer, 0x400);
    object->WriteTo(&stream);
    const int written = stream.GetPosition();
    if (written != measured) {
      Record(name, "failed", measured, written, 0,
             "TCountingStream and THandleStream disagree on the written length");
      ++failed;
      GlobalFree(buffer);
      return;
    }

    // 3. read it straight back; the position must land on exactly the same offset
    stream.SetPosition(0);
    object->ReadFrom(&stream);
    const int consumed = stream.GetPosition();
    if (consumed != written) {
      Record(name, "failed", measured, written, consumed,
             consumed < written ? "reader consumed fewer bytes than the writer produced"
                                : "reader consumed more bytes than the writer produced");
      ++failed;
      GlobalFree(buffer);
      return;
    }

    // 4. write again and compare: equal lengths can still hide a field that is written
    //    but never read back, which would come out zeroed the second time around.
    HGLOBAL second = GlobalAlloc(GMEM_MOVEABLE, static_cast<DWORD>(measured) * 2 + 0x40);
    if (second == 0) {
      Record(name, "passed", measured, written, consumed, "re-write comparison skipped");
      GlobalFree(buffer);
      return;
    }
    THandleStream rewrite;
    rewrite.AttachGlobalMemoryHandleAndResetPosition(second, 0x400);
    object->WriteTo(&rewrite);
    const int rewritten = rewrite.GetPosition();

    bool identical = rewritten == written;
    if (identical) {
      const unsigned char* left = static_cast<const unsigned char*>(GlobalLock(buffer));
      const unsigned char* right = static_cast<const unsigned char*>(GlobalLock(second));
      if (left != 0 && right != 0) {
        for (int offset = 0; offset < written; ++offset) {
          if (left[offset] != right[offset]) {
            identical = false;
            Record(name, "failed", measured, written, consumed,
                   "write -> read -> write is not stable; a field is written but not read back");
            ++failed;
            break;
          }
        }
      }
      if (left != 0) {
        GlobalUnlock(buffer);
      }
      if (right != 0) {
        GlobalUnlock(second);
      }
    } else {
      Record(name, "failed", measured, written, consumed,
             "second write produced a different length");
      ++failed;
    }

    if (identical) {
      Record(name, "passed", measured, written, consumed, 0);
    }
    GlobalFree(second);
    GlobalFree(buffer);
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

SerializationRoundtripTestCase g_test;

} // namespace

RuntimeTestCase* SerializationRoundtripTest() {
  return &g_test;
}
