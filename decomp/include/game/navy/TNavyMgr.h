#pragma once

#include "game/navy/TAdmiral.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/globals/shared_globals.h"

class TStream;
class TTaskForce;

// Result buffer filled by SelectEligibleMapOrderInteractionForNationAndContext for the
// first eligible queued interaction: the offering nation code, the packed exchange-
// direction flags (low 2 bits), and the chosen order entry.
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
  // Head of the global task-force order queue (was `void*`; retyped once
  // TTaskForce -- née TMapOrderEntry -- was RTTI-confirmed as the real
  // element class, see bd 1uj.16). TTaskForce::Free/OrderEvade/
  // OrderSailTowards (TTaskForce.cpp) all read/write this same
  // field via the g_pNavyOrderManager global.
  TTaskForce* orderQueueHead;

  // Mac oracle: WhoseIngotIsAt. First queued task force whose ingot sits on `tileIndex`,
  // or null. Walks orderQueueHead through nextForce. 0x0055a4d0, __thiscall.
  TTaskForce* WhoseIngotIsAt(short tileIndex);
  // Mac oracle: PrepareToCarryOutAllOrders(short). Stores the phase passed to that step.
  short executionPhase;
  char pad0a[2];
  // Transient task-force reference: CarryOutOrders' prologue (0x5578ad) is its only
  // confirmed reader/writer -- it Free()s the pointee (vtable slot 0x1c) if non-null,
  // then clears the pointer at the start of every
  // turn-phase order resolution pass.
  TTaskForce* pendingOrderEntry;

  void RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot);
  // Clears every cityScoreTable record's exploredByNationMaskA1 flag (dispatching a
  // per-province redraw-invalidate event through g_pGameFlowState while g_pSimMgr's
  // multiplayerSessionRole == 1, for each record found dirty), stores
  // `phaseId` into executionPhase, revalidates/requeues the map-order queue for the new turn
  // phase, then clears defeated across the whole orderQueueHead chain
  // (directly on the head, via RechargeAll for the rest). 0x5577b0.
  void PrepareToCarryOutAllOrders(short phaseId);
  // Mac oracle: MakeSureAllShipsHaveOrders(). Rebuilds and requeues every nation's
  // task force for each map-action zone before an execution phase.
  void MakeSureAllShipsHaveOrders(); // 0x557560

  // Finds the first orderQueueHead entry with shipOrders==7 (an escort task-force
  // order kind) and matching nation, then walks its shipList setting each
  // child's active: true if the child's strength is below its resource
  // type's stockCap column, otherwise a chancePercent-vs-rand()%100 coin flip. Returns
  // the matched entry (or null). 0x557e10.
  // Mac oracle: AssignEscorts(short, short).
  TTaskForce* AssignEscorts(short requiredCount, short chancePercent);

  // 0x5568f0 - stream out the three navy order lists (primary TShip chain tail-first,
  // TAdmiral secondary chain, orderQueueHead task-force chain), each prefixed with a
  // 16-bit count; nationFilter -1 serializes every nation's entries.
  void WriteToFilterously(TStream* stream, short nationFilter);
  // 0x556ad0 - receive-side twin of WriteToFilterously: rebuild the three
  // navy order lists from the stream for `nationFilter` (-1 = all nations).
  void ReadFromFilterously(TStream* stream, short nationFilter);
  // Mac oracle: FreeShipsOf(short). Cancels every queued task force for the nation,
  // then clears the transient primary-order flags on that nation's ships.
  void FreeShipsOf(short nation); // 0x556f60
  // Mac oracle: ClearAllOrders. The class-body definition is material: VC5 expands
  // it in Free() and retains its out-of-line COMDAT copy at 0x556850.
  // FUNCTION: IMPERIALISM 0x00556850
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
  // 0x557170. Walks typed task-force orders for the requested nation, province target,
  // and optional context-zone filter, then sums the active child ships' weighted cost.
  short GetInvasionCapacity(short nationSlot, Province* provinceTarget, TZone* contextFilter);

  // Mac oracle: CommitForce. If `entry` is already linked into orderQueueHead, returns
  // true (no-op). Otherwise, if `entry` has no live shipList entries,
  // frees it and returns false; else unlinks it from wherever it is
  // currently queued and (re)inserts it at orderQueueHead, returning true.
  bool CommitForce(TTaskForce* entry); // 0x557080

  // Mac oracle: ForgetForce, the counterpart to CommitForce directly above. Unlinks
  // `entry` from orderQueueHead and clears both of its queue links. Guards its own
  // receiver for null, as the original does. 0x00557120, __thiscall.
  void ForgetForce(TTaskForce* entry);

  // Called from TTaskForce::Encounter's tail
  // (ECX=g_pNavyOrderManager evidence at that callsite) when neither entry's priority
  // clears the other's threshold and no tie-break resolves it outright. Runs the
  // tier-scoring / random-attrition resolution between the two order entries' children.
  void ResolveStrategicBattle(TTaskForce* leftEntry, TTaskForce* rightEntry); // 0x55a780

  // Clears every primary ship's task-force backlink, destroys the whole
  // orderQueueHead task-force queue, clears the head, and notifies
  // g_pActiveMapOrderContext that no order entry is selected anymore.
  void ScuttleEverything(); // 0x556fd0

  // Mac oracle: ClearAllTransientOrders. Prunes the queued task-force chain and clears
  // the transient ready flag on every primary ship. 0x557040.
  void ClearAllTransientOrders();

  // 0x558960 (3485 bytes). Called twice in sequence from the map-order turn-phase
  // resolver (CarryOutOrders, 0x5578a0) with `mode` = 1 then 2
  // -- confirmed __thiscall on this (TNavyMgr) via the `MOV ECX,EBP; PUSH mode;
  // CALL` sequence at 0x557ca7/0x557cb1 and the callee's `RET 4`. Sweeps the 7
  // playable nations that have a live city, and for each its 17 tracked map-order
  // interaction slots, reading every queued entry via TGreatPower's tracked-slot
  // virtuals (GetTrackedSlotEntryCountLow @ slot 0x6d, ReadTrackedSlotEntryFields @
  // slot 0x6f). Each live entry builds a localized diplomacy/order-exchange event
  // message and, gated by `mode` (1 = offer pass, 2 = accept pass) and the selected
  // interaction's direction flags, applies the full exchange outcome: resource and
  // treasury transfers, capped-at-499 admiral/ship stat writes, per-nation counter
  // deltas, localized report rows, map-context action enqueueing, and tracked-slot
  // consumption. The tracked entry's payload is a treasury multiplier/value; the
  // selected TTaskForce comes from SelectEligibleMapOrderInteractionForNationAndContext.
  // The text receiver is g_pSimMgr (vtable 0x662a58; calls are
  // TSimMgr::GetStringPrelude/GetString).
  // 0x557f10 (1901 bytes). Scans orderQueueHead for the first queued order entry
  // whose interaction is eligible to fire this turn for `nation`: gates the nation's
  // own type-7 entry children by a priority-vs-descriptor roll, then for each
  // non-eliminated queued entry checks shipOrders/context match + diplomacy relation
  // (g_pDiplomacyTurnStateManager) and an order-score comparison (the same
  // TShip/TTaskForce::GetBattleStrengthRating /
  // ResolveStrategicBattle helpers the conflict resolver uses). On the first
  // eligible entry it fills `outResult` and returns 1; otherwise 0. `portZoneContext`
  // is the resolved TZone* (as int), `offerAmount` the transfer size.
  char
  SelectEligibleMapOrderInteractionForNationAndContext(TMapOrderInteractionSelection* outResult,
                                                       TZone* portZoneContext, short nation,
                                                       short offerAmount);

  void ProcessNationMapOrderInteractionsAndApplyOutcomes(short mode); // 0x558960

  // Mac oracle: CarryOutOrders. Per-turn-phase map-order conflict resolver: clears any
  // pending order-entry reference, then runs 6 filter/inner-loop passes over
  // orderQueueHead pairing competing order entries (3/4-vs-6, 6-vs-1, direct
  // type-1 apply, 3/4-vs-non-6, 1-vs-5 with an inlined threshold roll, direct
  // type-5/8 apply), returning immediately if any pairwise resolution reports a
  // result. Finishes by running the two-pass nation-interaction sweep,
  // rebuilding orderQueueHead via RemoveStragglers,
  // clearing the primary TShip list's transient selection flag, and refreshing the
  // active map-order context's overlays.
  void CarryOutOrders(); // 0x5578a0

  // Map-hover label lookups. These are real __thiscall members on the navy manager;
  // 0x559e00 additionally resolves the active task-force entry against the clicked
  // sea-zone or province context before choosing a cursor token.
  unsigned short ActionCursor(short nTileIndex, int nInputFlags);    // 0x559dd0
  unsigned short SelectionCursor(short nTileIndex, int nInputFlags); // 0x559e00

  // 0x0055a020 -- resolves and executes a context-sensitive map click action against this
  // manager's active map-order state (dialogs for actions 2..8, set-active-entry for 9,
  // UI-runtime slot 0xf0 for 10, entry-order dialog for 11 which walks orderQueueHead).
  // Returns true if the click was consumed. Ghidra's `int` prototype is a mislabel --
  // callers store the result in a `char fHandled` and test `!= '\0'`, and the real codegen
  // only ever sets/tests AL. Not virtual -- called directly (via an ILT thunk) from
  // TWorldView::HandleMapClickByInteractionMode and from DoTileClick.
  bool SelectionClick(short nTileIndex, int nInputFlags);
  // 0x0055a160 -- when a click is not consumed by immediate context handling, resolves a
  // map-order command from the active entry's tile-action/province context and runs the
  // set-type + rebuild/queue/finalize pipeline. Receiver at every call site is
  // g_pNavyOrderManager (this manager).
  int DoTileClick(short nTileIndex, int nInputFlags);

  // Mac name oracle: INavyMgr. Initializes the three global navy-order priority tables.
  void INavyMgr();

  TNavyMgr();
};

ASSERT_SIZE(TNavyMgr, 0x10);
