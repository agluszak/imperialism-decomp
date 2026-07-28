#include "game/globals/prelude.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00550d80
short GetResourceTypeRandomDrawBlockFlag(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].ResolveWeight();
}

// FUNCTION: IMPERIALISM 0x00550db0
short GetResourceDescriptorWord0CByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].CalculateWeight();
}

// FUNCTION: IMPERIALISM 0x00550de0
short GetResourceDescriptorWord10ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].TaskForceWeight();
}

// FUNCTION: IMPERIALISM 0x00550e10
short GetResourceDescriptorWord14ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].StockCap();
}

// FUNCTION: IMPERIALISM 0x00550e40
short GetResourceDescriptorWord18ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].NavyPriorityWeight();
}

// FUNCTION: IMPERIALISM 0x00550ea0
short GetResourceDescriptorWord20ByType(short resourceType) {
  return static_cast<short>(g_NavyOrderResourceDescriptorTable[resourceType].ToolbarBucketIndex());
}

// FUNCTION: IMPERIALISM 0x00550ed0
short GetResourceDescriptorWeightWord1ByType(short resourceType) {
  return g_NavyOrderResourceDescriptorTable[resourceType].DescriptorWeight();
}

// Generic accessor: reads the low short of the `statColumn`-th 4-byte column in the
// resourceType row (column 0=resolve weight, 1=calculate weight, 2=task-force weight,
// 3=stock cap, 4=navy-priority weight, 5=resource descriptor weight,
// 6=toolbar bucket index, 7=descriptor weight, 8=priority tier) -- matches the original's
// shipyard stat-panel indexing.
// FUNCTION: IMPERIALISM 0x00550f30
short GetResourceDescriptorStatByColumn(short resourceType, short statColumn) {
  return static_cast<short>(
      g_NavyOrderResourceDescriptorTable[resourceType].valueByColumn[statColumn]);
}
