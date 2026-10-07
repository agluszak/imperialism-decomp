#pragma once

#include "game/military/TArmyMission.h"

// Mac: TDefendProvinceMission — army defend-province mission.
// VTABLE: IMPERIALISM 0x0065a680
class TDefendProvinceMission : public TArmyMission {
  DECLARE_SERIAL(TDefendProvinceMission)
public:
  virtual ~TDefendProvinceMission() override; // slot 0x01 dtor 0x00535800 / ??_G
public:
  // Default constructor
  TDefendProvinceMission() : TArmyMission() {}

  TDefendProvinceMission(int nodeKey) : TArmyMission(nodeKey) {}

  virtual void Initialize() override; // slot 0x0c (TMission)
  virtual void
  Free() override; // slot 0x1c (TObject) 0x53ebe0 -- releases orderList and deletes self

  virtual bool IsANoBrainer() const override;
  virtual bool IsHospitalMission() const override;
  virtual void GiveOrders() override; // propagates target tile to linked units
  virtual TMission* GetReplacement() override;
  virtual bool Matches(eMissionType missionType, int key, TZone* zoneContext) const override;

  virtual void SetStateByte8To2() override;    // updates state by nation target match
  virtual void CalculateImportance() override; // computes terrain adjacency score
  virtual void CalculateNeeds() override;      // populates resource weights by diplomacy context

  static float ComputeLocalSupportVectorScore(int nodeContext);
  static float ComputeCrossNationSupportVectorScore(int nodeContext);
  float AssessImmediateThreat();

  void SetTargetTileForStack(short newTile);
};

bool IsTileCompatible(int tileIndex);

ASSERT_SIZE(TDefendProvinceMission, 0x30);
