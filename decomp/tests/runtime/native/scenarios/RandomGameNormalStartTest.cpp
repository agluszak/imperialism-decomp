#include "RuntimeGameStateCapture.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/globals/game_session_globals.h"
#include "game/globals/nation_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/city_ui/TCountry.h"

namespace {

CString HexRetailText(const CString& text) {
  static const char digits[] = "0123456789abcdef";
  CString hex;
  const unsigned char* bytes = reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(text));
  while (*bytes != 0) {
    hex += digits[*bytes >> 4];
    hex += digits[*bytes & 0x0f];
    ++bytes;
  }
  return hex;
}

// Normal difficulty parks at capital selection (event 0x3b8 / TCitySiteView) with the
// capital-selection prompt dismissed and no human capital placed yet. Capturing game_state
// here is the Rust create_random_game start-boundary oracle.
class RandomGameNormalStartTestCase : public CapitalSelectionScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    // Arrival at kRuntimeCapitalSelectionReady is the assertion; CaptureGameStateIfRequested
    // records the semantic GameState at result-write time while still parked here.
    RT_PASS();
    RT_END();
  }
};

class RandomNameGameNormalStartTestCase : public RandomGameNormalStartTestCase {
public:
  bool UsesLocalizedNames() const override {
    return false;
  }

protected:
  void Script() override {
    RT_BEGIN();
    CaptureNames();
    RT_PASS();
    RT_END();
  }

private:
  void CaptureNames() {
    MarkScriptStep("capture_random_province_names");
    JsonObject capture;
    JsonArray provinces;
    for (int id = 0; id < 0x180; ++id) {
      Province& province = g_pGlobalMapState->cityScoreTable[id];
      if (province.linkedTileIndices42[0] == -1) {
        continue;
      }
      JsonObject row;
      row.Set("id", id);
      CString hex = HexRetailText(province.cityNameA4);
      row.Set("name_hex", static_cast<LPCSTR>(hex));
      provinces.Add(row.Release());
    }
    capture.Set("provinces", provinces.Release());

    JsonArray nations;
    for (int slot = 0; slot < 0x17; ++slot) {
      TCountry* country = g_apTerrainTypeDescriptorTable[slot];
      if (country == 0) {
        continue;
      }
      CString name;
      country->LoadNationDisplayNameSharedRefFromField8(&name);
      JsonObject row;
      row.Set("slot", slot);
      CString hex = HexRetailText(name);
      row.Set("name_hex", static_cast<LPCSTR>(hex));
      nations.Add(row.Release());
    }
    capture.Set("nations", nations.Release());

    MarkScriptStep("capture_random_zone_names");
    JsonArray zones;
    TZone* zone = g_pMapActionContextListHead;
    for (int count = 0; zone != 0 && count < 0x70; ++count, zone = zone->prev18) {
      JsonObject row;
      row.Set("ordinal", static_cast<int>(zone->contextOrdinal14));
      row.Set("status_code", static_cast<int>(zone->statusCode04));
      CString hex = HexRetailText(zone->displayName);
      row.Set("display_name_hex", static_cast<LPCSTR>(hex));
      zones.Add(row.Release());
    }
    capture.Set("zones", zones.Release());
    MarkScriptStep("publish_random_game_names");
    RunState().SetCapture("random_game_names", capture.Release());
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RandomGameNormalStartTestCase, RandomGameNormalStartTest)
RUNTIME_TEST_FACTORY(RandomNameGameNormalStartTestCase, RandomNameGameNormalStartTest)
