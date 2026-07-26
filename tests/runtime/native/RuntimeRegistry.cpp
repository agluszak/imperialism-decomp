#include "RuntimeRegistry.h"

#include "scenarios/RuntimeScenarios.h"

#include <windows.h>

namespace {

RuntimeTestDescriptor g_descriptors[] = {
    {"boot_managers", BootManagersTest()},
    {"random_game_enters_map", RandomGameJourneyTest()},
    {"random_game_easy_skips_capital", EasyRandomGameTest()},
    {"random_game_introductory_exits_newspaper", IntroductoryRandomGameTest()},
    {"easy_turns_advance", EndTurnTest()},
    {"city_screen_opens", CityScreenTest()},
    {"civilian_recruitment_selection", CivilianRecruitmentTest()},
    {"diplomacy_screen_operates", DiplomacyScreenTest()},
    {"trade_screen_operates", TradeScreenTest()},
    {"map_zoom_toggle_remains_responsive", MapZoomToggleTest()},
    {"load_saved_game", LoadSavedGameTest()},
    {"turn_event_queue_bounds", TurnEventQueueBoundsTest()},
    {"serialization_roundtrip", SerializationRoundtripTest()},
    {"save_stream_checkpoints", SaveStreamCheckpointTest()},
    {"save_load_roundtrip", SaveLoadRoundtripTest()},
};

} // namespace

const RuntimeTestDescriptor* RuntimeRegistry::Find(const char* name) {
  for (int index = 0; index < DescriptorCount(); ++index) {
    if (lstrcmpA(g_descriptors[index].name, name) == 0) {
      return &g_descriptors[index];
    }
  }
  return 0;
}

const RuntimeTestDescriptor* RuntimeRegistry::Descriptors() {
  return g_descriptors;
}

int RuntimeRegistry::DescriptorCount() {
  return sizeof(g_descriptors) / sizeof(g_descriptors[0]);
}
