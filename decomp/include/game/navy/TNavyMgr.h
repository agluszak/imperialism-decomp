#pragma once

#include "game/navy/TAdmiral.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/globals/shared_globals.h"

class TStream;
class TTaskForce;

struct TMapOrderInteractionSelection {
  short offerNationCode;
  short pad02;
  unsigned int directionFlags; // +0x04 packed direction bits (bit0/bit1)
  TTaskForce* selectedEntry;
};

// VTABLE: IMPERIALISM 0x0065c4c8
class TNavyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNavyMgr)
  virtual ~TNavyMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  TTaskForce* orderQueueHead;

  TTaskForce* WhoseIngotIsAt(short tileIndex);
  short executionPhase;
  char pad0a[2];
  TTaskForce* pendingOrderEntry;

  void RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot);
  void PrepareToCarryOutAllOrders(short phaseId);
  void MakeSureAllShipsHaveOrders();

  TTaskForce* AssignEscorts(short requiredCount, short chancePercent);

  void WriteToFilterously(TStream* stream, short nationFilter);
  void ReadFromFilterously(TStream* stream, short nationFilter);
  void FreeShipsOf(short nation);
  void ClearAllOrders() {
    while (g_pNavyPrimaryOrderListHead != 0) {
      g_pNavyPrimaryOrderListHead->Free();
    }
    while (g_pNavySecondaryOrderListHead != 0) {
      g_pNavySecondaryOrderListHead->Free();
    }
    TTaskForce* orderHead = orderQueueHead;
    if (orderHead != 0) {
      orderHead->nextForce->FreeAll();
      orderHead->Free();
    }
  }
  short GetInvasionCapacity(short nationSlot, Province* provinceTarget, TZone* contextFilter);

  bool CommitForce(TTaskForce* entry);

  void ForgetForce(TTaskForce* entry);

  void ResolveStrategicBattle(TTaskForce* leftEntry, TTaskForce* rightEntry);

  void ScuttleEverything();

  void ClearAllTransientOrders();

  bool TryMerchantInterception(TMapOrderInteractionSelection* outResult, TZone* portZoneContext,
                               short nation, short offerAmount);

  void ProcessNationMapOrderInteractionsAndApplyOutcomes(short mode);

  void CarryOutOrders();

  unsigned short ActionCursor(short nTileIndex, int nInputFlags);
  unsigned short SelectionCursor(short nTileIndex, int nInputFlags);

  // ABI: callers store and test AL.
  bool SelectionClick(short nTileIndex, int nInputFlags);
  int DoTileClick(short nTileIndex, int nInputFlags);

  // Initializes the three global navy-order priority tables.
  void INavyMgr();

  TNavyMgr();
};

ASSERT_SIZE(TNavyMgr, 0x10);
