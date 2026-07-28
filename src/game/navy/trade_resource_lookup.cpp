#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

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

// Generic accessor: reads the low short of the `statColumn`-th 4-byte column in the
// resourceType row (column 0=resolveWeight, 1=calculateWeight, 2=taskForceWeight,
// 3=stockCap, 4=navyPriorityWeight, 5=resourceDescriptorWeightWord0,
// 6=enabledFlagOrBucketOffset, 7=descriptorWeight, 8=padding) -- matches the original's
// shipyard stat-panel indexing.
// FUNCTION: IMPERIALISM 0x00550f30
short GetResourceDescriptorStatByColumn(short resourceType, short statColumn) {
  return static_cast<short>(
      g_NavyOrderResourceDescriptorTable[resourceType].statColumnDwords[statColumn]);
}
