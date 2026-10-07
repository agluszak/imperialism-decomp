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
  ~TTaskForce() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;

  // LAYOUT: 0x34 bytes, own fields from +0x04.
  // ORACLE: eAgro; indexes the battle resolver's three aggression thresholds.
  int aggression;
  // ORACLE: eShipOrders, the submitted ship-order kind.
  int shipOrders;
  void* target;
  TMapOrderChildLinkNode* shipList;
  TShip* flagship;
  TZone* location;
  s16 nation;
  short shipCountsByToolbarSlot[4];
  char defeated;
  TTaskForce* previousForce;
  TTaskForce* nextForce;
  s16 ingotTileIndex;

  TTaskForce()
      : aggression(1), shipOrders(0), target(NULL), shipList(NULL), flagship(NULL), location(NULL),
        nation(-1), previousForce(NULL), nextForce(NULL), ingotTileIndex(-1) {
    memset(shipCountsByToolbarSlot, 0, sizeof(shipCountsByToolbarSlot));
  }

  TTaskForce(TZone* locationArg, short nationArg);

  void LinkTo(TTaskForce* prev_node, TTaskForce* next_node);

  void RegainVirginity(short nationArg, TZone* contextZone);
  void ITaskForce();
  short CountSelectedShips() const;
  void DemocraticallyDetermineAggressionLevel();
  void MaxOut(unsigned char mode);
  bool SinkOrSwimShips();
  void Victory(int experienceGain);

  void SetAggression(int value);
  void CommitToOrders();

  // Null-safe (returns true on null `this`). Sums shipCountsByToolbarSlot.
  bool IsEmpty() const;
  bool NoSelection() const;
  bool AllShipsSelected() const;
  char MouseCodeForTarget(Province* province) const;
  unsigned int IsValidTarget(Province* province);
  bool IsValidTarget(TZone* candidate);
  int IsPassingThroughPort(TZone* port) const;
  int MouseCodeForTarget(TZone* candidate) const;
  int GetNationalIndex() const;
  short CountForcesFromHere() const; // includes this node
  TTaskForce* GetNth(short index);
  static TTaskForce* GetNationalNth(short nth, short nation);
  // Clears this order's map marker tile if one is set (ingotTileIndex != -1).
  void DestroyIngot();
  void CreateIngot();
  void RechargeAll();

  void GetSnooperDescription(CString* out) const;

  void GetCompositionDescription(CString* out) const;
  void GetGeneralDescription(CString* out) const;
  TAdmiral* GetSeniorOfficer() const;
  void GetAuthority(CString* out) const;
  void CancelOrders(unsigned char cancellationMode);

  TTaskForce* RemoveStragglers();

  short CountShips() const;

  unsigned int GetWorstSpeed() const;

  void Select(TShip* ship, bool activeFlag);

  int GetInvasionCapacity() const;
  int GetSelected(short nationClass) const;

  int GetDeciSpeed() const;

  int GetBattleStrengthRating() const;

  void CarryOutOrders();

  bool AttemptToEvade(const TTaskForce* other);

  bool BattleWith(TTaskForce* other, TTaskForce*& unresolvedForce);

  bool IsAfraidOf(TTaskForce* other) const;

  bool Encounter(TTaskForce* other);

  bool TryToSpot(const TTaskForce* other) const;

  bool ResolveEncounterWith(TTaskForce* other);

  void DropShips(bool reserveExtraSlot);

  void Select(short toolbarSlot, unsigned char activeFlag);

  void FreeAll();

  // Folds Finest over shipList into flagship.
  void ElectFlagship();

  void FreeAvailables();

  void Remove(TShip* ship);

  // ORACLE: SubmitOrders(eShipOrders, void*); orderContext is a TZone* or Province*.
  void SubmitOrders(int orderType, void* orderContext);

  void OrderEvade();

  void OrderSailTowards(TZone* pContextAnchor);

  void OrderSail(TZone* orderTarget);
  void OrderBlockade(TZone* orderTarget);

  void OrderSendInTheMarines(Province* orderTarget);

  void OrderPatrol(bool useType4);

  void Add(TShip* node);
};

ASSERT_SIZE(TTaskForce, 0x34);
