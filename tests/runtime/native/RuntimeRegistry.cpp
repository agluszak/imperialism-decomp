#include "RuntimeRegistry.h"

#include "scenarios/LegacyJourneyTest.h"

#include <windows.h>

namespace {

LegacyJourneyTest g_legacyJourneyTest;

RuntimeTestDescriptor g_descriptors[] = {
    {"boot_managers", &g_legacyJourneyTest},
    {"random_game_enters_map", &g_legacyJourneyTest},
    {"random_game_easy_skips_capital", &g_legacyJourneyTest},
    {"easy_turns_advance", &g_legacyJourneyTest},
    {"city_screen_opens", &g_legacyJourneyTest},
    {"load_saved_game", &g_legacyJourneyTest},
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
