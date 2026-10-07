#pragma once

#include "game/map/TNavyMission.h"
#include "game/globals/military_globals.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/navy_globals.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/navy/TShip.h"

// VTABLE: IMPERIALISM 0x0065a740
class TControlSeaZoneMission : public TNavyMission {
  DECLARE_SERIAL(TControlSeaZoneMission)
public:
  // Inline so beachhead and blockade destructors emit the original direct CObject teardown.
  // FUNCTION: IMPERIALISM 0x00535620
  virtual ~TControlSeaZoneMission() override {}

public:
  TControlSeaZoneMission() : TNavyMission() {}

  TControlSeaZoneMission(TZone* targetZone) : TNavyMission(targetZone) {}

  virtual void
  Initialize() override; // slot 0x0c 0x5387f0 -- port-zone-context score recompute (shared)
  virtual void
  SetStateByte8To2() override; // slot 0x0d 0x538fe0 -- state update from target navy similarity
  virtual void
  CalculateImportance() override; // slot 0x0e 0x539290 -- port-zone-context average score (shared)
  virtual void
  CalculateNeeds() override; // slot 0x0f 0x5393a0 -- resource weights from allied navy pressure

  virtual TMission* GetReplacement()
      override; // slot 0x12 0x538900 -- validate terrain coverage / refresh target (shared)
  virtual bool Matches(eMissionType missionType, int key,
                       TZone* zoneContext) const override; // slot 0x13 0x539600

  virtual bool IsDefensiveSeaZoneMission() const override; // slot 0x18 0x5355d0
  virtual bool IsHospitalMission() const override;         // slot 0x19 0x5355b0

  virtual void GiveActionOrders(TTaskForce* mapOrderEntry)
      override; // slot 0x27 0x539640 -- resolve+queue port-zone map order
  virtual TZone* PickAmassingZone() override; // slot 0x28 0x539780 (shared)
};

ASSERT_SIZE(TControlSeaZoneMission, 0x3c);

// Inline: TBeachheadMission and TBlockadePortMission expand it in retail.
// FUNCTION: IMPERIALISM 0x005393a0
inline void TControlSeaZoneMission::CalculateNeeds() {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* node = TShip::GetFirst(); node != NULL; node = node->next) {
    if (node->location != missionTargetZone) {
      continue;
    }
    if (!g_pDiplomacyTurnStateManager->AreAtWar(nationId, node->nation)) {
      continue;
    }
    short normalizationBase = node->GetMaxStrength();
    float scale = static_cast<float>(node->strength / normalizationBase);
    vector[0] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * scale;
    vector[1] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * scale;
    vector[2] +=
        static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * scale;
    vector[3] += static_cast<float>(node->ComputeNavyOrderPriorityContributionPercentByCategory(3));
  }

  const short* lookupTable = g_Populate_Beachhead_Mission_LookupTable;
  float sum = vector[0] + vector[1] + vector[2] + vector[3];
  float total = 0.0f;
  if (sum != 0.0f) {
    float delta = 0.0f;
    for (int i = 0; i < 4; ++i) {
      float diff = vector[i] / sum - static_cast<float>(static_cast<short>(lookupTable[i])) * 0.01;
      if (diff <= 0.0f) {
        diff = -diff;
      }
      delta += diff;
    }
    total = sum * (1.0f - delta * 0.5f);
  }
  total *= g_MissionResourceWeightScale;
  if (total == 0.0f) {
    total = g_MissionEmptyResourceWeight;
  }

  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] =
        static_cast<float>(static_cast<short>(lookupTable[i])) * total * 0.01;
  }
}
