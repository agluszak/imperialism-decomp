#include "RuntimeRegistry.h"

#include "RuntimeHarnessCore.h"

// The generated descriptor names turn events by their C++ constant, so the numbers
// stay in one place rather than being duplicated into the catalog.
#include "game/turn_event_codes.h"

// Both generated from tools/runtime/catalog.py by generate_native_registry.py, so a test's
// registered name and its factory declaration cannot drift apart.
#include "RuntimeScenarioFactories.inc"

namespace {

#include "RuntimeRegistry.inc"

} // namespace

const RuntimeTestDescriptor* RuntimeRegistry::Find(const char* name) {
  int index = FindRuntimeDescriptorIndex(name, g_descriptors, DescriptorCount());
  return index >= 0 ? &g_descriptors[index] : 0;
}

const RuntimeTestDescriptor* RuntimeRegistry::Descriptors() {
  return g_descriptors;
}

int RuntimeRegistry::DescriptorCount() {
  return sizeof(g_descriptors) / sizeof(g_descriptors[0]);
}
