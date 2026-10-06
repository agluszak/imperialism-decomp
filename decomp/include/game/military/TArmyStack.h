#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class TMilitaryUnit;
class TStream;

// Owned singly linked nodes holding non-owning military-unit pointers.
struct TArmyStackUnitNode {
  TMilitaryUnit* unit;      // +0x00
  TArmyStackUnitNode* next; // +0x04
};
ASSERT_SIZE(TArmyStackUnitNode, 8);

// VTABLE: IMPERIALISM 0x0064ca38
class TArmyStack : public TObject {
public:
  DECLARE_DYNCREATE(TArmyStack)
  virtual ~TArmyStack() override;                  // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a7960
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a77b0
  virtual void Free() override;                    // slot 0x07 0x4a7c20
  short field4;                                    // +0x04 -- composition class
  short field6;                                    // +0x06 -- composition class and random sort key
  signed char categoryFlag;
  unsigned char fortLevelAttackerPenaltyCache;
  short unitCountA;     // +0x0a -- linked unit count, serialized as a signed word
  unsigned char fieldC; // +0x0c -- initialized by IArmyStack
  unsigned char padD;
  short ownerNationCodeE; // +0x0e -- region/owner-nation code
  short tileIndex10;      // +0x10 -- originating tile index / order-target province
  unsigned char pad12[2];
  TArmyStackUnitNode* head14;   // +0x14 -- head of the owned node chain
  TArmyStackUnitNode* cursor18; // +0x18 -- traversal cursor over the chain

  void ReseatChainUnitsAndClearOrders();

  void ComputeStackCompositionClassCode();

  void InitializeStrategicBattle(unsigned char boosted);

  TMilitaryUnit* ResetCursorAndGetHeadUnit();
  TMilitaryUnit* AdvanceCursorAndGetUnit();

  void AddUnitByRosterId(short rosterID);
  void RaiseExperience(bool boosted);
  bool UnitsFighting(); // 0x4a8330, Mac oracle
  void StrategicFirepower(int* outWeightedSum, int* outCount, int counter);
  void ApplyStrategicDamage(int weightedSum, int count, int counter);
  void IArmyStack(char ownerNationIndex, short ownerNationCode, short tileIndex);
  void AddUnitToChainHead(TMilitaryUnit* unit);
  void RemoveUnitFromChain(TMilitaryUnit* unit);

  TArmyStack();
};
ASSERT_SIZE(TArmyStack, 0x1c);
