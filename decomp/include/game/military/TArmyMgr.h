#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/map_order_battle_snapshot.h"
#include "game/mfc.h"

class TStream;
class TSortedList;
class TArmyStack;
struct TextStyle;

struct MapContextActionRecord {
  unsigned char nationIds[2];              // +0x00
  unsigned char reportParticipantIndex;    // +0x02
  unsigned char displayedParticipantIndex; // +0x03, serialized
  MapContextReportKindStorage reportKind;  // +0x04
  void* location;                          // +0x08
  // LAYOUT: +0x0c..+0x257 match the per-side tail of MapOrderBattleSnapshot.
  CStr32 nameBuffer[2];    // +0x0c/+0x2c
  CStr255 overlayLabel[2]; // +0x4c/+0x14b
  short childCount24a[2];  // +0x24a/+0x24c
  unsigned char pad24e[2]; // +0x24e (alignment pad before the pointer array)
  // Owned per-side arrays, released by CleanUpStacks.
  MapOrderBattleSideChildRecord* sideChildRecords[2]; // +0x250/+0x254
  int markerPixelX;                                   // +0x258
  int markerPixelY;                                   // +0x25c
  unsigned char placedFlag;                           // +0x260
  unsigned char pad261;                               // +0x261
  short markerSpriteCode;                             // +0x262
  short listOrdinal;                                  // +0x264
  unsigned char pad266[0x268 - 0x266];

  ~MapContextActionRecord() {
    delete[] sideChildRecords[0];
    delete[] sideChildRecords[1];
  }

  void ReadFrom(TStream* stream); // 0x4a13c0
  void WriteTo(TStream* stream);  // 0x4a1640
};

// VTABLE: IMPERIALISM 0x0064c928
class TArmyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TArmyMgr)
  virtual ~TArmyMgr() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a1dd0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a1b80
  virtual void Free() override;                    // slot 0x07 0x4a1a00
  // Retail Mac identities, confirmed against the Windows call chain and bodies.
  virtual void DoCombatMoves(); // slot 0x0a 0x4a1e40
  virtual void FormStacks();    // slot 0x0b 0x4a1f80
  // Moves or fights each pending stack from nextStackOrdinal until a battle view opens.
  virtual void ResolveNextMove();                            // slot 0x0c 0x4a2390
  virtual void ClearPendingStacksAndFinalizeMilitaryUnits(); // slot 0x0d 0x4a2500
  // Splits the stack into our and enemy units; relocates peacefully or opens a battle.
  virtual bool ResolveConflict(TArmyStack* stack,
                               short ownerNationCode); // slot 0x0e 0x4a3200
  // Retreats the stack's movable units to a random adjacent friendly region.
  virtual void RetreatDefender(TArmyStack* stack,
                               short tileIndex);   // slot 0x0f 0x4a35e0
  virtual void RetreatAttacker(TArmyStack* stack); // slot 0x10 0x4a37b0
  virtual bool StrategicCombat(TArmyStack* stack1,
                               TArmyStack* stack2); // slot 0x11 0x4a3830
  virtual void DoOwnershipChanges();                // slot 0x12 0x4a3bc0
  // tileActionCode 1/4 selects a unit (slot 0x14); 7 commits the action cost (slot 0x15).
  virtual void DispatchTileActionByKind(int contextArg,
                                        short tileActionCode); // slot 0x13 0x4a3d90
  // contextArg is the TUnit::SetOrders payload; returns whether a unit was commanded.
  virtual bool SelectMovableUnitOnCurrentTileAndPlaySfx(int contextArg); // slot 0x14 0x4a3e50
  // Returns whether the tile's move cost was affordable and committed.
  virtual bool CommitCityActionGateCostIfAffordable(int contextArg); // slot 0x15 0x4a3f30
  virtual void SetOrdersForIdleUnitsOnPendingTile(int mode);         // slot 0x16 0x4a4260
  virtual bool HandleMapClickByComputedCursorState(short tileIndex,
                                                   short mode); // slot 0x17 0x4a4870
  // Civilian-cursor counterpart of HandleMapClickByComputedCursorState.
  virtual bool HandleMapClickByCivilianCursorState(short tileIndex,
                                                   short mode); // slot 0x18 0x4a4ad0

  // Weighted strength of the units stationed in the province. ABI: thiscall on the
  // singleton; the body ignores `this`. 0x004a5aa0.
  int ComputeWeightedNeighborLinkScoreForNodeIndex(int nodeIndex);

  // Battle records (MapContextActionRecord) for this turn's reports.
  class TSortedPtrList* mapContextActionRecordList;
  // Set by every appended battle record; CleanUpStacks clears it.
  bool battlesToReport;
  unsigned char pad09[0x0c - 0x09];
  // Stacks built by FormStacks and walked by ResolveNextMove.
  class TArmyStackList* pendingUnitPool;
  // One-based ResolveNextMove cursor into pendingUnitPool.
  int nextStackOrdinal;
  // Static tables (0x695448/0x695428) the constructor stores; nothing reads them.
  const void* staticTable14;
  const void* staticTable18;
  // Province owner codes FormStacks caches before moving stacks.
  short perTileOwnerNationCodeCache1c[0x180];
  void DispatchMapActionForRegionByAdjacency(int contextArg);

  short pendingMapActionIndex; // selected province, -1 when none
  // Per-side summary DoTacticalCombat builds for the battle UI.
  signed char tacticalCombatNationCode31e[2];
  short tacticalCombatContext;
  short tacticalCombatUnitCountByType322[2][30];
  // Consumed by EndBattlePhase.
  bool needsTerrainRefreshFlag;
  unsigned char pad39b;
  // Battle participants cached for EndBattlePhase.
  class TArmyStack* ourStackBattle;
  class TArmyStack* enemyStackBattle;
  class TArmyBattle* activeBattleView;

  void WakeAll(int nationId);

  void DoTacticalCombat(TArmyStack* ourStack, TArmyStack* enemyStack, int battleContext);

  void EndBattlePhase();

  // Select the first matching unit and return how many remain in the other state.
  // ABI: thiscall on the singleton; the bodies ignore `this`.
  short ActivateFirstIdleTacticalUnitByCategoryAtTile(short categoryId, short tileIndex);
  short ActivateFirstActiveTacticalUnitByCategoryAtTile(short categoryId, short tileIndex);

  // Whether the province holds an idle military unit. 0x004a4550.
  bool AnySelectableUnits(short regionId);

  int GetSelectedForceSize();

  // Selects a province (-1 clears), resetting its units' order modes. 0x004a45e0.
  void SetSelectedProvince(short cityRecordIndex);
  void ClearProvinceSelectionHighlightsForNation(short nationId);
  short FindNextSelectableProvinceForNation(short nationId);

  // ABI: thiscall on the singleton; the bodies ignore `this`.
  unsigned short LookupMapCursorTokenByStateIndex(short tileIndex, short mode); // 0x4a4930
  unsigned short LookupCivilianMapCursorTokenByStateIndex(short tileIndex,
                                                          short mode); // 0x4a4aa0

  // Civilian counterpart of ComputeMapCursorStateIndex. 0x004a4c80.
  int ComputeCivilianMapCursorStateIndex(short tileIndex, short mode);
  bool ValidateOrderPlacementPrerequisitesForSelectedTile(short cityRecordIndex);
  void MarchSelectedArmies(short tileIndex);
  void CreateTacticalBattleViewAndInitializeBattleSetup(TArmyStack* ourStack,
                                                        TArmyStack* enemyStack,
                                                        int ownerNationCodeInt);
  void ShowSpyReport(int cityRecordIndex);

  bool GenerateSpyReport(int cityRecordIndex, CString& outDefenderSummary,
                         CString& outGarrisonSummary);

  void TrimExcessNavyOrderSupportAndRebuildOrderBuffer(char nationId, int cityIndex,
                                                       struct MapOrderBattleSnapshot* snapshot);

  bool HasBattlesToReport() const; // Mac oracle; 0x4a6dd0

  void CleanUpStacks();

  void EndTacticalBattle(TArmyStack* ourStack, TArmyStack* enemyStack, unsigned char sideWonFlag,
                         int battleSiteIndex);

  void AddBattleRecord(struct MapOrderBattleSnapshot* record, int unusedArg2);
  void IArmyMgr();

  bool HasBattlesInvolvingGP(short activeNationId) const;

  void ReassessLanding(int nationSlot, int zone);

  TArmyMgr();
};
ASSERT_SIZE(TArmyMgr, 0x3a8);
