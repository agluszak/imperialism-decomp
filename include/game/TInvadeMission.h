#pragma once

#include "game/TAttackProvinceMission.h"

class TBeachheadMission;

// Mac: TInvadeMission — TAttackProvinceMission variant that also drives an
// amphibious TBeachheadMission child (beachhead34) when the target province
// is not directly reachable overland.
// VTABLE: IMPERIALISM 0x0065aec0
class TInvadeMission : public TAttackProvinceMission {
  DECLARE_SERIAL(TInvadeMission)
public:
  TBeachheadMission* beachhead34; // +0x34 owned amphibious-landing child mission

  TInvadeMission();
  TInvadeMission(short targetProvince, TZone* beachheadZone);

  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x53f640
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x53f690
  virtual void Free() override;                    // slot 0x07 0x53f410

  virtual int ReturnZeroSlot2C(int* outBuffer, int unused) override; // slot 0x0b 0x53fc10

  virtual void Call30() override;           // slot 0x0c 0x53f580 -- init from nation/target tile
  virtual void SetStateByte8To2() override; // slot 0x0d 0x53f5f0 -- state08 = 2
  virtual void NoOpSlot3C() override; // slot 0x0f 0x53f610 -- updates invade+beachhead child state

  virtual void RefreshSlot40() override; // slot 0x10 0x53f7d0 -- advance composite handlers
  virtual void MissionSlot44() override; // slot 0x11 0x53f780 -- refresh beachhead node / repath
  virtual TMission*
  GetReplacementSlot48() override; // slot 0x12 0x53fe10 -- reset target terrain class + refresh
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) override; // slot 0x13 0x53fbc0

  virtual char ReturnFalseSlot50() override; // slot 0x14 0x53faa0
  virtual char ReturnFalseSlot54() override; // slot 0x15 0x53f140

  virtual int ReturnZeroSlot5C() override; // slot 0x17 0x53f120 -- returns beachhead34

  virtual char ReturnFalseSlot64() override; // slot 0x19 0x53f240

  virtual float
  ReturnZeroFloatSlot6C() override; // slot 0x1b 0x53f1f0 -- composite score with beachhead
  virtual float ReturnZeroFloatSlot70(
      TMilitaryUnit* candidateUnit) override; // slot 0x1c 0x53fac0 -- weighted score delta
  virtual float ReturnZeroFloatSlot74(
      void* candidate) override; // slot 0x1d 0x53fb60 -- beachhead score if enabled

  virtual void NoOpSlot84(void* a,
                          int b) override; // slot 0x21 0x53f190 -- forward to beachhead slot 0x84
  virtual void NoOpSlot8C(void* a,
                          int b) override;   // slot 0x23 0x53f1c0 -- forward to beachhead slot 0x8c
  virtual void NoOpSlot90(void* a) override; // slot 0x24 0x53f160 -- forward to beachhead slot 0x90
  virtual void SetFlag10FromArgSlot94(unsigned char value) override; // slot 0x25 0x53fb90

  virtual char
  ReturnFalseSlot98() override; // slot 0x26 0x53f4e0 -- evaluate beachhead + queue eligible units

  virtual char TryResolveTargetTerrainClass() override; // slot 0x28 0x53fdc0
};

ASSERT_SIZE(TInvadeMission, 0x38);
