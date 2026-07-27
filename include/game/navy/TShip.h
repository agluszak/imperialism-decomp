#pragma once

#include "game/ui_screens/CString.h"
#include "game/app/TObject.h"

class TAdmiral;
class TGreatPower;
class TMission;
class TStream;
class TTaskForce;
class TZone;
struct CRuntimeClass;

// Navy primary-order node ("ship" in the original architecture -- the Mac oracle's
// TShip carries the full naval-unit API; the Windows port has so far recovered its
// order/roster/serialization face). Every instance lives on the global roster list
// (head g_pNavyPrimaryOrderListHead @ 0x6A3EDC): TShip() prepends itself and
// Free() unlinks. A ship can additionally be queued as a child order node under a
// TTaskForce entry (taskForce + the entry's shipList /
// TNavyMission::orderList24 link cells -- TMapOrderChildLinkNode payloads are
// TShip* in both lists).
// VTABLE: IMPERIALISM 0x0065c438
class TShip : public TObject {
public:
  short type;
  short pad06;
  TZone* location;

  // Plain setter for `location`. 0x0054fc60, __thiscall.
  void SetLocation(TZone* zone);
  // Parent map-order entry this node is queued under (cleared by ReassignToForce /
  // the entry-side prune paths).
  TTaskForce* taskForce;
  // Cached copy of the owning task force's eAgro dword.
  int aggression;
  short nation;
  CString name;
  short strength;
  short pad1e;
  // Backlink to the TAdmiral whose assignedShip is this node (TAdmiral::
  // TAdmiral::AssignToShip writes `this` here).
  TAdmiral* admiral;
  TShip* next;
  TShip* previous;
  // Owning mission backlink: TNavyMission slot-0x84 attach writes `this` mission
  // here, slot-0x8C detach nulls it (TGreatPower's assignment scan checks it for
  // "unassigned").
  TMission* mission;
  // Per-ship experience, stored in hundred-point tiers by the naval scoring code.
  // Mac oracle: Victory(int) raises it and caps it at 499; ModByExp(int) and
  // Finest(TShip*, unsigned char) consume the same value.
  short experience;
  unsigned char pad32[2];
  int selection;

  TShip();
  ~TShip() override;

  DECLARE_DYNCREATE(TShip)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  static TShip* GetFirst();
  static TShip* GetNth(short index);

  // Per-category (0-3) priority-contribution percentage for this order node, used
  // by callers that accumulate a 4-component category vector. Sibling of
  // GetStudliness (same lookup tables, different blend
  // per category). 0x54ff00; every call site walks ship nodes (the primary
  // roster or an orderList24/shipList chain).
  short ComputeNavyOrderPriorityContributionPercentByCategory(int category);
  // Per-type normalization base (the "stock cap" field of the shared
  // per-resource-type descriptor table); inline wrapper over the by-resource-type
  // lookup, never emitted out of line.
  short GetMaxStrength() const;
  // 0x00550b60 — composite economic score of this order node (quantity + descriptor
  // weights, normalized by the task-force weight).
  int GetStudliness() const;
  // Mac oracle: IsInHomePort() const. The Windows body forwards to
  // location's TZone::QueryPortZoneCapability virtual. 0x00550f60.
  bool IsInHomePort() const;
  // Position of `this` in the primary navy order roster, counted from
  // g_pNavyPrimaryOrderListHead (used when serializing orderList24 nodes by index;
  // Mac oracle: TShip::GetIndex).
  int GetIndex() const;
  // BFS zone-graph "hop" distance from this ship's own zone (location) to
  // `otherZone`, blended against this resource type's descriptorWeight column
  // (Mac oracle: TShip::GetTurnDistanceTo(TZone*)).
  short GetTurnDistanceTo(TZone* otherZone) const;
  // 0x005509c0 -- marks this node depleted (strength = -666) and re-prunes the
  // owning order entry's child list; with no owner it just Free()s this node.
  void Sink();

  // Per-type descriptor-table reads (0x550510 / 0x550820).
  short GetToolbarSlot() const;
  short GetRange() const;
  // Node-score family (0x550840 / 0x550aa0): descriptor-blended scores of this
  // order node's strength/stock.
  int GetSpeed() const;
  // Mac oracle: GetBattleStrengthRating() const.
  int GetBattleStrengthRating() const;
  // 0x00550f80 -- strength -= decrement (battle losses commit path).
  void Damage(short decrement);
  // 0x005501b0 -- 4-category priority score of this order node against score
  // profile `nScoreProfileId` (same descriptor/divisor tables as the per-category
  // contribution scorer).
  int ComputeValueForMission(int missionType) const;
  // Mac oracle: Victory(int). The Windows ABI passes the experience gain as a short.
  void Victory(short experienceGain); // 0x00550370
  // 0x005503a0 -- returns this ship's owner entry, unless the owner has other
  // children too (then this ship is split off it: unlinked from the owner's
  // shipList, bucket counter decremented, active child recomputed) or there
  // is no owner; in both of those cases a fresh TTaskForce entry is created around
  // this ship (zone context = location, nation = nation) and returned.
  TTaskForce* DemandExclusiveTaskForce();
  // 0x00550670 -- priority compare between two ships: admiral experiencePoints first,
  // then type, then experience/100 tiers, then strength; returns the
  // preferred node. With preferUnassignedFlag, an admiral-assigned receiver loses
  // to the candidate outright (and vice versa).
  TShip* Finest(TShip* candidate, unsigned char preferUnassigned);
  // 0x00550ff0 -- detaches this ship from its owner entry's shipList
  // (decrementing the owner's per-resource-type bucket counter and recomputing its
  // preferred active child), then re-attaches it under `newOwnerEntry` when given.
  void ReassignToForce(TTaskForce* newOwnerEntry);
  // 0x00551100 -- hands this ship order node to `nation` (naval capture): detaches
  // it from its owner entry (unless already that nation's), notifies/detaches the
  // owning mission via its slot-0x8C when the mission belongs to another nation,
  // then writes nation.
  void Capture(short nation);
  // 0x00551220 -- sets taskForce and caches the entry's aggression; entry kinds outside
  // {0,4,7,8} also zero selection.
  void SetTaskForce(TTaskForce* newEntry);
};

ASSERT_SIZE(TShip, 0x38);
