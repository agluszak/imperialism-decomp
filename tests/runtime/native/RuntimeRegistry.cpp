#include "RuntimeRegistry.h"

#include "RuntimeHarnessCore.h"
#include "scenarios/RuntimeScenarios.h"

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
