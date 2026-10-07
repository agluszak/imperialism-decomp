#pragma once

#include "game/map/TMinister.h"

class TLongintList;

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ec140
  virtual ~TDefenseMinister() override {} // slot 0x01 (scalar deleting destructor)
  TDefenseMinister();
  void IDefenseMinister(TGreatPower* owner);

  void InitializeOrderArrayPreset50_0_10_50(TGreatPower* owner);  // 0x4ed560
  void InitializeOrderArrayPreset10_10_10_50(TGreatPower* owner); // 0x4ed890
  void InitializeOrderArrayPreset15_20_50_75(TGreatPower* owner); // 0x4edb80
  void InitializeOrderArrayPreset20_10_10_50(TGreatPower* owner); // 0x4ede60
  void InitializeOrderArrayPreset25_10_20_50(TGreatPower* owner); // 0x4ee150

  DECLARE_DYNCREATE(TDefenseMinister)
  void WriteTo(TStream* stream) override;                    // 5 (0x4ec1d0)
  void ReadFrom(TStream* stream) override;                   // 6 (0x4ec2f0)
  short GetRankingCriterionForGP(short nationSlot) override; // 0x0a (0x4ec3d0)

  // New virtuals introduced by TDefenseMinister (vtable 0x6549b0, bytes 0x48-0x60).
  virtual void GoShopping();            // 0x48 (0x4ec450), Mac oracle
  virtual void DoArmyMovement();        // 0x4c (0x4ec4c0), Mac oracle
  virtual void DoPeacetimeDeployment(); // 0x50 (0x4ec540), Mac oracle
  virtual unsigned char*
  CreatePeaceDefenseMap(TLongintList* ownedRegions);                 // 0x54 (0x4ecbb0), Mac oracle
  virtual int* CreateHomeValueMap();                                 // 0x58 (0x4ecf20), Mac oracle
  virtual int* CreateEnemyPowerMap(unsigned char excludeEnemyTiles); // 0x5c (0x4ed050), Mac oracle
  virtual double GetStategicEscalationMultiplier(bool flag);         // Mac oracle spelling

  short field10;
  short field12;
  short recruitOrderCountByType[0x1e]; // +0x14..0x50
  short orderWeightTableB[0x1e];       // +0x50..0x8c
  short thresholdA;                    // +0x8c
  short thresholdB;                    // +0x8e
  short thresholdC;                    // +0x90
  short thresholdD;                    // +0x92
};

ASSERT_SIZE(TDefenseMinister, 0x94);
