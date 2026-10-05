#pragma once

#include "game/navy/TAdmiral.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/globals/shared_globals.h"

class TStream;
class TTaskForce;

struct TMapOrderInteractionSelection {
  short offerNationCode;       // +0x00
  short pad02;                 // +0x02
  unsigned int directionFlags; // +0x04 packed direction bits (bit0/bit1)
  TTaskForce* selectedEntry;   // +0x08
};

// VTABLE: IMPERIALISM 0x0065c4c8
class TNavyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNavyMgr)
  virtual ~TNavyMgr() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5568c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x556aa0
  virtual void Free() override;                    // slot 0x07 0x5567a0
  TTaskForce* orderQueueHead;

  TTaskForce* WhoseIngotIsAt(short tileIndex);
  short executionPhase;
  char pad0a[2];
  TTaskForce* pendingOrderEntry;

  void RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot);
  void PrepareToCarryOutAllOrders(short phaseId);
  void MakeSureAllShipsHaveOrders(); // 0x557560

  TTaskForce* AssignEscorts(short requiredCount, short chancePercent);

  void WriteToFilterously(TStream* stream, short nationFilter);
  void ReadFromFilterously(TStream* stream, short nationFilter);
  void FreeShipsOf(short nation); // 0x556f60
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

  bool CommitForce(TTaskForce* entry); // 0x557080

  void ForgetForce(TTaskForce* entry);

  void ResolveStrategicBattle(TTaskForce* leftEntry, TTaskForce* rightEntry); // 0x55a780

  void ScuttleEverything(); // 0x556fd0

  void ClearAllTransientOrders();

  char
  TryMerchantInterception(TMapOrderInteractionSelection* outResult,
                                                       TZone* portZoneContext, short nation,
                                                       short offerAmount);

  void ProcessNationMapOrderInteractionsAndApplyOutcomes(short mode); // 0x558960

  void CarryOutOrders(); // 0x5578a0

  unsigned short ActionCursor(short nTileIndex, int nInputFlags);    // 0x559dd0
  unsigned short SelectionCursor(short nTileIndex, int nInputFlags); // 0x559e00

  // 0x0055a020 -- resolves and executes a context-sensitive map click action against this
  // manager's active map-order state (dialogs for actions 2..8, set-active-entry for 9,
  // UI-runtime slot 0xf0 for 10, entry-order dialog for 11 which walks orderQueueHead).
  // ABI: callers store and test AL. Called directly (via an ILT thunk) from
  // TWorldView::NormalClick and from DoTileClick.
  bool SelectionClick(short nTileIndex, int nInputFlags);
  int DoTileClick(short nTileIndex, int nInputFlags);

  // Mac name oracle: INavyMgr. Initializes the three global navy-order priority tables.
  void INavyMgr();

  TNavyMgr();
};

ASSERT_SIZE(TNavyMgr, 0x10);
