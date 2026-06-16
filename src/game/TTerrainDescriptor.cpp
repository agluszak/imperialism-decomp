#include "game/TTerrainDescriptor.h"

#include "game/TCountry.h"
#include "game/TGlobalMapState.h"
#include "game/TPtrList.h"
#include "game/TStationedUnitNode.h"
#include "game/diplomacy_globals.h"

int DecodeTerrainNationSlotFromDescriptor(const TCountry* terrain, short encodedNationSlot) {
  if (encodedNationSlot < 200) {
    if (encodedNationSlot < 100) {
      return terrain->nationSlot;
    }
    return encodedNationSlot - 100;
  }
  return encodedNationSlot - 200;
}

int ResolveTerrainNationSlotFromTarget(int targetNationSlot) {
  const TCountry* terrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
  return DecodeTerrainNationSlotFromDescriptor(terrain, terrain->encodedNationSlot);
}

static const unsigned int kAddrWeightedNeighborScoreByUnitType = 0x006955F0;

// FUNCTION: IMPERIALISM 0x004a5aa0
int ComputeWeightedNeighborLinkScoreForNodeIndex(short nodeIndex) {
  if (nodeIndex < 0 || nodeIndex > 0x17f) {
    return 0;
  }
  TStationedUnitNode* chain = g_pGlobalMapState->cityScoreTable[nodeIndex].stationedUnitChain98;
  int sum = 0;
  for (; chain != 0; chain = chain->next14) {
    sum += *reinterpret_cast<int*>(kAddrWeightedNeighborScoreByUnitType + chain->unitTypeId04 * 4);
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004d8390
int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex) {
  return ComputeWeightedNeighborLinkScoreForNodeIndex(static_cast<short>(nodeIndex));
}

// FUNCTION: IMPERIALISM 0x004d83c0
int SumWeightedNeighborLinkScoreForLinkedNodes(TCountry* terrain) {
  int sum = 0;
  TPtrList* linkedList = terrain->ownedRegionList;
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
    sum += ComputeWeightedNeighborLinkScoreForNodeIndex(static_cast<short>(nodeId));
    ++index;
    count = linkedList->GetCountOrReleaseSlot28();
  } while (index <= count);

  return sum;
}
