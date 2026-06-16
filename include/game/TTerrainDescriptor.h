#pragma once

#include "game/TPtrList.h"

class TTerrainDescriptor {
public:
  virtual void dummy0() = 0;
  virtual void dummy1() = 0;
  virtual void dummy2() = 0;
  virtual void dummy3() = 0;
  virtual void dummy4() = 0;
  virtual void dummy5() = 0;
  virtual void dummy6() = 0;
  virtual void dummy7() = 0;
  virtual void dummy8() = 0;
  virtual void dummy9() = 0;
  virtual void dummy10() = 0;
  virtual void dummy11() = 0;
  virtual void dummy12() = 0;
  virtual void dummy13() = 0;
  virtual void CallSlot38(int delta) = 0; // slot 38
  virtual void dummy15() = 0;
  virtual void dummy16() = 0;
  virtual void dummy17() = 0;
  virtual void dummy18() = 0;
  virtual void CallSlot4C(int sourceNation, int modeValue) = 0; // slot 4C
  virtual void dummy20() = 0;
  virtual void dummy21() = 0;
  virtual void dummy22() = 0;
  virtual void dummy23() = 0;
  virtual void dummy24() = 0;
  virtual void dummy25() = 0;
  virtual void SetResetLevelSlot68(int sourceNation, int resetLevel) = 0; // slot 68

  unsigned char pad04[0x0c - 0x04];
  // +0x0c/+0x0e — nation-slot pair consumed by the join-empire decode paths
  // (encoded slot >= 200 -> minor, >= 100 -> major-100, else fall back to +0x0c).
  short fallbackNationSlot0c;
  short encodedNationSlot0e;
  unsigned char pad10[0x90 - 0x10];
  // +0x90 — TPtrList of linked map nodes (region development sweep, 0x004e72c0).
  TPtrList* linkedNodeList90;

protected:
  ~TTerrainDescriptor() {}
};

int DecodeTerrainNationSlotFromDescriptor(const TTerrainDescriptor* terrain,
                                          short encodedNationSlot);
int ResolveTerrainNationSlotFromTarget(int targetNationSlot);
int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex);
int ComputeWeightedNeighborLinkScoreForNodeIndex(short nodeIndex);
int SumWeightedNeighborLinkScoreForLinkedNodes(TTerrainDescriptor* terrain);
