#pragma once

#include "game/core/CString.h"
#include "game/app/TObject.h"

class TAdmiral;
class TGreatPower;
class TMission;
class TStream;
class TTaskForce;
class TZone;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x0065c438
class TShip : public TObject {
public:
  short type;
  short pad06;
  TZone* location;

  // Plain setter for `location`. 0x0054fc60, __thiscall.
  void MoveTo(TZone* zone);

  void IShip(short shipType, TZone* zone, short nationArg, const char* nameOverride);
  void NameThyself();
  TTaskForce* taskForce;
  // Cached copy of the owning task force's eAgro dword.
  int aggression;
  short nation;
  CString name;
  short strength;
  short pad1e;
  TAdmiral* admiral;
  TShip* next;
  TShip* previous;
  TMission* mission;
  short experience;
  unsigned char pad32[2];
  int selection;

  TShip();
  ~TShip() override;

  DECLARE_DYNCREATE(TShip)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  static void FreeAll();
  static TShip* GetFirst();
  static TShip* GetLast();
  // Mac oracle per-type stats from g_NavyOrderResourceDescriptorTable.
  static short GetTypeFirepower(short shipType);    // 0x550d80
  static short GetTypeBattleRange(short shipType);  // 0x550db0
  static short GetTypeArmor(short shipType);        // 0x550de0
  static short GetTypeHullPoints(short shipType);   // 0x550e10
  static short GetTypeBattleSpeed(short shipType);  // 0x550e40
  static short GetTypeCargoHold(short shipType);    // 0x550e70
  static short GetTypeToolbarSlot(short shipType);  // 0x550ea0
  static short GetTypeSailingSpeed(short shipType); // 0x550ed0
  static short GetTypeStat(short shipType, short statColumn); // 0x550f30, Mac oracle
  static TShip* GetNth(short index);
  static short GetTypeSlot(short shipType);
  static int GetTypeAttribute(int attribute, short shipType);

  short ComputeNavyOrderPriorityContributionPercentByCategory(int category);
  short GetMaxStrength() const;
  int GetStudliness() const;
  bool IsInHomePort() const;
  int GetIndex() const;
  short GetTurnDistanceTo(TZone* otherZone) const;
  void Sink();

  // Per-type descriptor-table reads (0x550510 / 0x550820).
  short GetToolbarSlot() const;
  short GetRange() const;
  short GetArmorFactor() const;
  int GetInvasionCapacity() const;
  int ModByExp(int value) const;
  float ModByExp(float value) const;
  int GetSpeed() const;
  short GetBattleSpeed() const;
  int GetFirepower() const;
  // Mac oracle: GetBattleStrengthRating() const.
  int GetBattleStrengthRating() const;
  // 0x00550f80 -- strength -= decrement (battle losses commit path).
  void Damage(short decrement);
  void Repair();
  int ComputeValueForMission(int missionType) const;
  // Mac oracle: Victory(int). The Windows ABI passes the experience gain as a short.
  void Victory(short experienceGain); // 0x00550370
  TTaskForce* DemandExclusiveTaskForce();
  TShip* Finest(TShip* candidate, bool preferUnassigned);
  void ReassignToForce(TTaskForce* newOwnerEntry);
  void Capture(short nation);
  void SetTaskForce(TTaskForce* newEntry);
};

ASSERT_SIZE(TShip, 0x38);
