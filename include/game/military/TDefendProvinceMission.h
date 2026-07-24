#pragma once

#include "game/military/TArmyMission.h"

// Mac: TDefendProvinceMission — army defend-province mission.
// VTABLE: IMPERIALISM 0x0065a680
class TDefendProvinceMission : public TArmyMission {
  DECLARE_SERIAL(TDefendProvinceMission)
public:
  virtual ~TDefendProvinceMission() override; // slot 0x01 dtor 0x00535800 / ??_G 0x005357d0
public:
  // Default constructor
  TDefendProvinceMission() : TArmyMission() {}

  // Delegates to TArmyMission(nodeKey) and stamps this class's vtable; inlined into the
  // mission factory (TMission::CreateMission case 3, param_4 == 0), no standalone address.
  TDefendProvinceMission(int nodeKey) : TArmyMission(nodeKey) {}

  virtual void Initialize() override; // slot 0x0c (TMission) 0x53eff0
  virtual void
  Free() override; // slot 0x1c (TObject) 0x53ebe0 -- releases orderListAt18 and deletes self

  virtual bool IsANoBrainer() const override;      // slot 0x28 0x5357b0
  virtual bool IsHospitalMission() const override; // slot 0x64 0x535790
  virtual void
  GiveOrders() override; // slot 0x44 0x535770 -- propagates target tile to linked units
  virtual TMission* GetReplacementSlot48() override; // slot 0x48 0x53f040
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x4c 0x53f010

  // These override TMission's own slots 0x0d/0x0e/0x0f (SetStateByte8To2 /
  // CalculateImportance / CalculateNeeds) with DefendProvinceMission-specific bodies.
  virtual void
  SetStateByte8To2() override; // slot 0x34 0x53ecc0 -- updates state by nation target match
  virtual void
  CalculateImportance() override; // slot 0x38 0x53ed00 -- computes terrain adjacency score
  virtual void CalculateNeeds()
      override; // slot 0x3c 0x53edf0 -- populates resource weights by diplomacy context

  static float ComputeLocalSupportVectorScore(int nodeContext);
  static float ComputeCrossNationSupportVectorScore(int nodeContext);

  // Walks orderListAt18 and re-issues TUnit::SetOrders(kUnitOrderRedeploy, newTile) on every
  // linked TMilitaryUnit whose tileIndex06 differs from newTile (propagating this
  // mission's new target tile to units still ordered against the old one). 0x53c950.
  void PropagateTargetTileToLinkedUnitsIfDifferent(short newTile);
};

bool IsMapTileCompatibleWithCurrentTerrainOrActionContext(int tileIndex);

ASSERT_SIZE(TDefendProvinceMission, 0x30);
