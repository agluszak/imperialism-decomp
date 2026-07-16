#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TObject.h"

class TZone;
class TMilitaryUnit;

// Mac oracle: eMissionType -- the mission-kind selector passed to the mission factory
// (CreateMissionObjectByKindAndNodeContext) and to TMission::Matches. The Windows
// binary only exposes the integer values 0..5; enumerator names below are provisional,
// taken from the mission each kind primarily constructs (several kinds fall back to a
// TControlSeaZoneMission when their context/beachhead argument is absent).
enum eMissionType {
  kMissionTypeAttackProvince = 0, // TAttackProvinceMission (direct) / TControlSeaZoneMission
  kMissionTypeAmassProvince = 1,  // TAttackProvinceMission with an amassing province
  kMissionTypeInvadeProvince = 2, // TInvadeMission / TControlSeaZoneMission
  kMissionTypeDefendProvince =
      3,                        // TDefendProvinceMission / TEscortMission / TControlSeaZoneMission
  kMissionTypeBlockadePort = 4, // TBlockadePortMission
  kMissionTypeScatteredShips = 5, // TScatteredShipsMission
};

// Mac: TMission — base AI-mission class. Real polymorphic MFC object rooted at
// CObject<-TObject (slot 0x00 RTTI, dtor resets vptr to the CObject sentinel
// 0x66fec4). Single-inheritance base of TNavyMission / TArmyMission (and through
// them every concrete mission); proven by vtable prefix-sharing and ctor sequencing
// (ConstructTArmyMissionWithNodeKey calls ConstructTMission then installs its vtable).
//
// 48-slot vtable: slots 0x00-0x04 are the MFC CObject prefix (0x00 RTTI + 0x01 dtor
// overridden here; 0x02 Serialize / 0x03 AssertValid / 0x04 Dump inherited). Slots
// 0x05-0x26 are TMission's own virtuals (mostly default stubs concrete missions
// override). Slots 0x27-0x2f are pure virtuals (NULL in the base table). See memory
// tmission-vtable-layout-ground-truth.
//
// VTABLE: IMPERIALISM 0x0065a4e8
class TMission : public TObject {
public:
  short nationId04;      // 0x04 source-nation id (InitializeMission...)
  short pathMarker06;    // 0x06 path/dispatch marker (set 0xffff)
  unsigned char state08; // 0x08 lifecycle state byte (ctor = 2)
  unsigned char padding09[3];
  float value0c;          // 0x0c cached score/value (ctor = 0.0f)
  unsigned char flag10;   // 0x10 dispatch flag (SetMissionField10FromArgSlot94)
  unsigned char marker11; // 0x11 status byte (ctor = 0xff)
  unsigned char padding12[2];

  TMission();

  // --- MFC CObject prefix slots 0x00-0x04 ---
  DECLARE_SERIAL(TMission)
  virtual ~TMission() override; // 0x01 dtor 0x535080 / ??_G 0x535050
  // 0x02 Serialize / 0x03 AssertValid / 0x04 Dump inherited from CObject.

  // --- TMission's own virtuals, exact vtable slot order ---
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x535820
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5358a0
  virtual char ReturnFalseSlot28(); // 0x0a 0x534c00 — mission-node queue dispatch (0x004daa80)
  virtual int ReturnZeroSlot2C(int* outBuffer, int unused);          // 0x0b 0x534c20 (ret 8)
  virtual void Call30();                                             // 0x0c 0x534c40 (NoOpSlot30)
  virtual void SetStateByte8To2();                                   // 0x0d 0x534c60
  virtual void ResetValue0CToZero();                                 // 0x0e 0x534c80
  virtual void NoOpSlot3C();                                         // 0x0f 0x534ca0
  virtual void RefreshSlot40();                                      // 0x10 0x534cc0
  virtual void MissionSlot44();                                      // 0x11 0x534cf0
  virtual TMission* GetReplacementSlot48();                          // 0x12 0x534d10
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode); // 0x13 0x534d30
  virtual char ReturnFalseSlot50();                                  // 0x14 0x534d50
  virtual char ReturnFalseSlot54();                                  // 0x15 0x534d70
  virtual int ReturnZeroSlot58();                                    // 0x16 0x534d90
  virtual int ReturnZeroSlot5C();                                    // 0x17 0x534db0
  virtual char ReturnFalseSlot60();                                  // 0x18 0x534dd0
  virtual char ReturnFalseSlot64();                                  // 0x19 0x534df0
  virtual float ReturnZeroFloatSlot68();                             // 0x1a 0x534e10
  virtual float ReturnZeroFloatSlot6C();                             // 0x1b 0x534e30
  virtual float ReturnZeroFloatSlot70(
      TMilitaryUnit* candidateUnit); // 0x1c 0x534e70 (ret 4 -- verified against base stub)
  virtual float ReturnZeroFloatSlot74(void* candidate); // 0x1d 0x534e50 (ret 4 -- navy
                                                        // overrides read a TShip order node)
  virtual float ReturnZeroFloatSlot78(
      TMilitaryUnit* candidateUnit,
      float* referenceVector); // 0x1e 0x534eb0 (ret 8 -- verified against base stub)
  virtual float ReturnZeroFloatSlot7C(void* candidate,
                                      void* targetProfile); // 0x1f 0x534e90 (ret 8)
  virtual void NoOpSlot80(TMilitaryUnit* unit, int notify); // 0x20 0x534ef0 — AdoptUnitSlot80
  virtual void NoOpSlot84(int a, int b);                    // 0x21 0x534ed0 (ret 8)
  virtual void NoOpSlot88(TMilitaryUnit* unit, int unused); // 0x22 0x534f30
  virtual void NoOpSlot8C(int a, int b);                    // 0x23 0x534f10
  virtual void NoOpSlot90(int a);                           // 0x24 0x534f50
  virtual void SetFlag10FromArgSlot94(unsigned char value); // 0x25 0x534f70
  virtual char ReturnFalseSlot98();                         // 0x26 0x534f90

  void DispatchMissionNodeSlot28() {
    (void)ReturnFalseSlot28();
  }
  void AdoptUnitSlot80(TMilitaryUnit* unit, int flag) {
    NoOpSlot80(unit, flag);
  }

  // Slots 0x27-0x2f are NULL in the base table (abstract: filled only by derived
  // classes). Not declared here — C++ pure virtuals would emit _purecall, not NULL,
  // and the next derived class (TNavyMission/TArmyMission) appends its own virtuals
  // starting at slot 0x27. (Same convention as TUberCluster's abstract-null region.)
};

ASSERT_SIZE(TMission, 0x14);

// Mission factory (0x5350d0, __cdecl): allocates and constructs the concrete mission
// subtype selected by missionKind, stamps the common owner/marker fields, and runs the
// mission's Call30 initializer. contextArg is the map-order context / target port zone
// (a TZone) for the navy missions; nodeKey/keyArg carry province or amassing keys.
TMission* CreateMissionObjectByKindAndNodeContext(int sourceNation, eMissionType missionKind,
                                                  int nodeKey, int contextArg, int keyArg);
