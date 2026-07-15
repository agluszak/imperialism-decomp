#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00550d80
short GetResourceTypeRandomDrawBlockFlag(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].resolveWeight;
}

// FUNCTION: IMPERIALISM 0x00550db0
short GetResourceDescriptorWord0CByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].calculateWeight;
}

// FUNCTION: IMPERIALISM 0x00550de0
short GetResourceDescriptorWord10ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].taskForceWeight;
}

// FUNCTION: IMPERIALISM 0x00550e10
short GetResourceDescriptorWord14ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].stockCap;
}

// FUNCTION: IMPERIALISM 0x00550e40
short GetResourceDescriptorWord18ByType(short resourceType) {
  return static_cast<short>(g_NavyOrderResourceDescriptorTable[resourceType].navyPriorityWeight);
}

// FUNCTION: IMPERIALISM 0x00550ea0
short GetResourceDescriptorWord20ByType(short resourceType) {
  return static_cast<short>(
      g_NavyOrderResourceDescriptorTable[resourceType].enabledFlagOrBucketOffset);
}

// FUNCTION: IMPERIALISM 0x00550ed0
short GetResourceDescriptorWeightWord1ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].descriptorWeight;
}

// Generic accessor: reads the low short of the `subslot`-th 4-byte int-sized column in
// the resourceType row (subslot 0=resolveWeight, 1=calculateWeight, 2=taskForceWeight,
// 3=stockCap, 4=navyPriorityWeight, 5=resourceDescriptorWeightWord0,
// 6=enabledFlagOrBucketOffset, 7=descriptorWeight, 8=padding) -- matches the original's
// own generic int-indexed-then-short-read pattern rather than a per-column switch.
// FUNCTION: IMPERIALISM 0x00550f30
short GetResourceDescriptorWord08ByTypeOffset(short resourceType, short subslot) {
  const int* row = reinterpret_cast<const int*>(&g_NavyOrderResourceDescriptorTable[resourceType]);
  return *reinterpret_cast<const short*>(row + subslot);
}
