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

  // Plain setter for `location`.
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
  static short GetTypeFirepower(short shipType);
  static short GetTypeBattleRange(short shipType);
  static short GetTypeArmor(short shipType);
  static short GetTypeHullPoints(short shipType);
  static short GetTypeBattleSpeed(short shipType);
  static short GetTypeCargoHold(short shipType);
  static short GetTypeToolbarSlot(short shipType);
  static short GetTypeSailingSpeed(short shipType);
  static short GetTypeStat(short shipType, short statColumn);
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
  int GetBattleStrengthRating() const;
  void Damage(short decrement);
  void Repair();
  int ComputeValueForMission(int missionType) const;
  void Victory(short experienceGain);
  TTaskForce* DemandExclusiveTaskForce();
  TShip* Finest(TShip* candidate, bool preferUnassigned);
  void ReassignToForce(TTaskForce* newOwnerEntry);
  void Capture(short nation);
  void SetTaskForce(TTaskForce* newEntry);
};

ASSERT_SIZE(TShip, 0x38);
