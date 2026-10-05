#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/navy/TMapOrderChildLinkNode.h"
#include "game/navy/TShip.h"
#include "game/globals/navy_globals.h"

class TStream;
class CString;
class TZone;
struct Province;

// VTABLE: IMPERIALISM 0x0065c468
class TTaskForce : public TObject {
public:
  DECLARE_DYNCREATE(TTaskForce)
  ~TTaskForce() override;                          // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x552b90
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x552d10
  virtual void Free() override;                    // slot 0x07 0x552930

  // LAYOUT: TObject occupies +0x00..+0x03; TTaskForce fields begin at +0x04 and the
  // complete object is 0x34 bytes.
  // ORACLE: eAgro. SetAggression writes the complete dword, ships cache the
  // complete dword, and the battle resolver uses it to index its three-entry
  // aggression threshold table.
  int aggression;
  // ORACLE: eShipOrders. This is the submitted ship-order kind. TNavyMgr's
  // RemoveMatchingTaskForceOrders (0x557170 cluster) checks this == 5 for
  // "task force" queue entries; OrderEvade (0x552f80) sets it to
  // 9 for the map-order-9 kind.
  int shipOrders;
  void* target;
  TMapOrderChildLinkNode* shipList; // +0x10
  TShip* flagship; // +0x14
  TZone* location; // +0x18
  s16 nation;
  short shipCountsByToolbarSlot[4];
  char defeated;
  char pad_27;
  TTaskForce* previousForce;
  TTaskForce* nextForce;
  s16 ingotTileIndex;
  char pad_32[0x02];

  TTaskForce()
      : aggression(1), shipOrders(0), target(nullptr), shipList(nullptr), flagship(nullptr),
        location(nullptr), nation(-1), previousForce(nullptr), nextForce(nullptr),
        ingotTileIndex(-1) {
    memset(shipCountsByToolbarSlot, 0, sizeof(shipCountsByToolbarSlot));
  }

  TTaskForce(TZone* locationArg, short nationArg);

  void LinkTo(TTaskForce* prev_node, TTaskForce* next_node);

  // ORACLE: RegainVirginity(int, TZone*). Removes every child ship and resets
  // the task force's nation/context identity for a new map selection.
  void RegainVirginity(int nationArg, TZone* contextZone); // 0x552a70
  void ITaskForce();
  short CountSelectedShips() const;
  // 0x005548e0 — averages each child's cached aggression and stores the rounded result.
  void DemocraticallyDetermineAggressionLevel();
  void MaxOut(unsigned char mode);
  char SinkOrSwimShips();
  void Victory(int experienceGain); // 0x553e70

  // Mac oracle: SetAggression(eAgro).
  void SetAggression(int value); // 0x552f60
  void CommitToOrders();

  // Null-safe (returns true on null `this`). Sums shipCountsByToolbarSlot.
  bool IsEmpty() const; // 0x553b10
  bool NoSelection() const; // 0x553b50
  bool AllShipsSelected() const;
  char MouseCodeForTarget(Province* province) const;
  unsigned int IsValidTarget(Province* province);
  // ORACLE: Mac TTaskForce::IsValidTarget(TZone*). A selected force can target a zone
  // when its cached graph distance does not exceed the slowest selected ship's movement
  // weight. 0x005544a0.
  bool IsValidTarget(TZone* candidate);
  int IsPassingThroughPort(TZone* port) const;
  int MouseCodeForTarget(TZone* candidate) const;
  int GetNationalIndex() const; // 0x5563d0
  short CountForcesFromHere() const; // 0x5562f0, includes this node
  TTaskForce* GetNth(short index);   // 0x556340
  static TTaskForce* GetNationalNth(short nth, short nation);
  // Clears this order's map marker tile if one is set (ingotTileIndex != -1).
  void DestroyIngot(); // 0x5564f0
  void CreateIngot(); // 0x556410
  void RechargeAll(); // 0x557870

  void GetSnooperDescription(CString* out) const; // 0x554c90

  void GetCompositionDescription(CString* out) const; // 0x554b20
  void GetGeneralDescription(CString* out) const; // 0x554e70
  TAdmiral* GetSeniorOfficer() const;                // 0x5551a0
  void GetAuthority(CString* out) const;             // 0x5551d0
  void CancelOrders(unsigned char cancellationMode); // 0x5547d0

  TTaskForce* RemoveStragglers();

  short CountShips() const; // 0x5562c0

  unsigned int GetWorstSpeed() const; // 0x554a80

  void Select(TShip* ship, bool activeFlag); // 0x5549a0

  int GetInvasionCapacity() const;          // 0x5549f0
  int GetSelected(short nationClass) const; // 0x554a30

  int GetDeciSpeed() const; // 0x554ad0

  int GetBattleStrengthRating() const; // 0x556010

  void CarryOutOrders(); // 0x556100

  bool AttemptToEvade(const TTaskForce* other); // 0x555c20

  bool BattleWith(TTaskForce* other, TTaskForce*& unresolvedForce); // 0x555d10

  bool IsAfraidOf(TTaskForce* other) const; // 0x555de0

  bool Encounter(TTaskForce* other); // 0x555420

  bool TryToSpot(const TTaskForce* other) const; // 0x555720

  bool ResolveEncounterWith(TTaskForce* other); // 0x555920

  void DropShips(bool reserveExtraSlot); // 0x553a50

  void Select(short toolbarSlot, unsigned char activeFlag); // 0x554930

  void FreeAll(); // 0x556820

  // Folds Finest over shipList into flagship.
  void ElectFlagship(); // 0x553e30

  void FreeAvailables(); // 0x553f10

  // ORACLE: Remove(TShip*). Removes the ship's child link, updates its class count and
  // preferred-child cache, then clears the ship's owner backlink.
  void Remove(TShip* ship); // 0x553d40

  // ORACLE: SubmitOrders(eShipOrders, void*). orderContext is interpreted as a
  // TZone* or Province* according to orderType.
  void SubmitOrders(int orderType, void* orderContext); // 0x5540b0

  void OrderEvade(); // 0x552f80

  void OrderSailTowards(TZone* pContextAnchor); // 0x5533f0

  // OrderSail uses map-order kind 1. OrderBlockade stores the port-zone context in
  // target, sets shipOrders=6, then follows the OrderEvade cleanup/queue tail.
  // ORACLE: OrderSail.
  void OrderSail(TZone* orderTarget);     // 0x553270
  void OrderBlockade(TZone* orderTarget); // 0x5536c0

  void OrderSendInTheMarines(Province* orderTarget); // 0x553840

  void OrderPatrol(bool useType4); // 0x5530f0

  void Add(TShip* node); // 0x553bc0
};

ASSERT_SIZE(TTaskForce, 0x34);
