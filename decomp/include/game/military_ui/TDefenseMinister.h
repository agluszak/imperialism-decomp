#pragma once

#include "game/map/TMinister.h"

class TLongintList;

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ec140
  virtual ~TDefenseMinister() override {}
  TDefenseMinister();
  void IDefenseMinister(TGreatPower* owner);

  DECLARE_DYNCREATE(TDefenseMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short GetRankingCriterionForGP(short nationSlot) override;

  // New virtuals introduced by TDefenseMinister (vtable 0x6549b0, bytes 0x48-0x60).
  virtual void GoShopping();
  virtual void DoArmyMovement();
  virtual void DoPeacetimeDeployment();
  virtual unsigned char* CreatePeaceDefenseMap(TLongintList* ownedRegions);
  virtual int* CreateHomeValueMap();
  virtual int* CreateEnemyPowerMap(unsigned char excludeEnemyTiles);
  virtual double GetStategicEscalationMultiplier(bool flag); // Mac oracle spelling

  short field10;
  short field12;
  short recruitOrderCountByType[0x1e];
  short orderWeightTableB[0x1e];
  short thresholdA;
  short thresholdB;
  short thresholdC;
  short thresholdD;
};

ASSERT_SIZE(TDefenseMinister, 0x94);
