#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class TMilitaryUnit;
class TStream;

// Owned singly linked nodes holding non-owning military-unit pointers.
struct TArmyStackUnitNode {
  TMilitaryUnit* unit;
  TArmyStackUnitNode* next;
};
ASSERT_SIZE(TArmyStackUnitNode, 8);

// VTABLE: IMPERIALISM 0x0064ca38
class TArmyStack : public TObject {
public:
  DECLARE_DYNCREATE(TArmyStack)
  virtual ~TArmyStack() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  short compositionClass; // composition class
  short sortKey;          // composition class and random sort key
  signed char categoryFlag;
  unsigned char fortLevelAttackerPenaltyCache;
  short unitCount;      // linked unit count, serialized as a signed word
  unsigned char fieldC; // initialized by IArmyStack
  unsigned char padD;
  short ownerNationCode; // region/owner-nation code
  short tileIndex;       // originating tile index / order-target province
  unsigned char pad12[2];
  TArmyStackUnitNode* head14; // head of the owned node chain
  TArmyStackUnitNode* cursor; // traversal cursor over the chain

  void MoveAll();

  void ComputeStackCompositionClassCode();

  void InitializeStrategicBattle(unsigned char boosted);

  TMilitaryUnit* ResetCursorAndGetHeadUnit();
  TMilitaryUnit* AdvanceCursorAndGetUnit();

  void AddUnitByRosterId(short rosterID);
  void RaiseExperience(bool boosted);
  bool UnitsFighting();
  void StrategicFirepower(int* outWeightedSum, int* outCount, int counter);
  void ApplyStrategicDamage(int weightedSum, int count, int counter);
  void IArmyStack(char ownerNationIndex, short ownerNationCode, short tileIndex);
  void AddUnit(TMilitaryUnit* unit);
  void RemoveUnit(TMilitaryUnit* unit);

  TArmyStack();
};
ASSERT_SIZE(TArmyStack, 0x1c);
