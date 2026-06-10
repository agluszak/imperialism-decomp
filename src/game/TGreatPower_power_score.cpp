#include "game/TGreatPower.h"

#include "decomp_types.h"
#include "game/TTerrainDescriptor.h"
#include "game/TPtrList.h"

undefined4 ComputeWeightedNeighborLinkScoreForNodeIndex(void);

static int CallWeightedNeighborLinkScoreForNodeIndex(int nodeIndex) {
  return reinterpret_cast<int(__cdecl*)(int)>(ComputeWeightedNeighborLinkScoreForNodeIndex)(nodeIndex);
}

// FUNCTION: IMPERIALISM 0x004d8390
int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex) {
  return CallWeightedNeighborLinkScoreForNodeIndex(nodeIndex);
}

// FUNCTION: IMPERIALISM 0x004d83c0
int SumWeightedNeighborLinkScoreForLinkedNodes(TTerrainDescriptor* terrain) {
  int sum = 0;
  TPtrList* linkedList = terrain->linkedNodeList90;
  if (linkedList == 0) {
    return 0;
  }

  int index = 1;
  int count = linkedList->GetCountOrReleaseSlot28();
  if (count <= 0) {
    return 0;
  }

  do {
    int nodeId = linkedList->GetIntByOrdinalSlot24(index);
    sum += CallWeightedNeighborLinkScoreForNodeIndex(nodeId);
    ++index;
    count = linkedList->GetCountOrReleaseSlot28();
  } while (index <= count);

  return sum;
}

// FUNCTION: IMPERIALISM 0x004e0420
#pragma optimize("y", on)
void TGreatPower::VTableSlot84_Provisional(int targetNation) {
  (void)targetNation;
}
#pragma optimize("", on)
