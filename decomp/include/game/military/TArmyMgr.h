#pragma once

#include "game/map_domain_types.h"
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
  unsigned char nationIds[2];
  unsigned char reportParticipantIndex;
  unsigned char displayedParticipantIndex; // serialized
  MapContextReportKindStorage reportKind;
  void* location;
  // LAYOUT: +0x0c..+0x257 match the per-side tail of MapOrderBattleSnapshot.
  CStr32 nameBuffer[2];
  CStr255 overlayLabel[2];
  short childCount[2];
  // Owned per-side arrays, released by CleanUpStacks.
  MapOrderBattleSideChildRecord* sideChildRecords[2];
  int markerPixelX;
  int markerPixelY;
  bool placedFlag;
  short markerSpriteCode;
  short listOrdinal;

  ~MapContextActionRecord() {
    delete[] sideChildRecords[0];
    delete[] sideChildRecords[1];
  }

  void ReadFrom(TStream* stream);
  void WriteTo(TStream* stream);
};

// VTABLE: IMPERIALISM 0x0064c928
class TArmyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TArmyMgr)
  virtual ~TArmyMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  // Retail Mac identities, confirmed against the Windows call chain and bodies.
  virtual void DoCombatMoves();
  virtual void FormStacks();
  // Moves or fights each pending stack from nextStackOrdinal until a battle view opens.
  virtual void ResolveNextMove();
  virtual void FinishArmyMoves();
  // Splits the stack into our and enemy units; relocates peacefully or opens a battle.
  virtual bool ResolveConflict(TArmyStack* stack, short ownerNationCode);
  // Retreats the stack's movable units to a random adjacent friendly region.
  virtual void RetreatDefender(TArmyStack* stack, short tileIndex);
  virtual void RetreatAttacker(TArmyStack* stack);
  virtual bool StrategicCombat(TArmyStack* stack1, TArmyStack* stack2);
  virtual void DoOwnershipChanges();
  // tileActionCode 1/4 selects a unit (slot 0x14); 7 commits the action cost (slot 0x15).
  virtual void OrderArmies(int contextArg, short tileActionCode);
  // contextArg is the TUnit::SetOrders payload; returns whether a unit was commanded.
  virtual bool MoveArmies(int contextArg);
  // Returns whether the tile's move cost was affordable and committed.
  virtual bool DeploySelectedArmies(int contextArg);
  virtual void OrderSelectedArmies(int mode);
  virtual bool HandleMapClickByComputedCursorState(short tileIndex, short mode);
  // Civilian-cursor counterpart of HandleMapClickByComputedCursorState.
  virtual bool HandleMapClickByCivilianCursorState(short tileIndex, short mode);

  // ABI: thiscall on the singleton; the body ignores `this`.
  int GetLandForceIn(int nodeIndex);

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
  short perTileOwnerNationCodeCache[kProvinceCount];
  void DispatchMapActionForRegionByAdjacency(int contextArg);

  short pendingMapActionIndex; // selected province, -1 when none
  // Per-side summary DoTacticalCombat builds for the battle UI.
  signed char tacticalCombatNationCode[2];
  short tacticalCombatContext;
  short tacticalCombatUnitCountByType[2][30];
  // Consumed by EndBattlePhase.
  bool needsTerrainRefreshFlag;
  // Battle participants cached for EndBattlePhase.
  class TArmyStack* ourStackBattle;
  class TArmyStack* enemyStackBattle;
  class TArmyBattle* activeBattleView;

  void WakeAll(int nationId);

  void DoTacticalCombat(TArmyStack* ourStack, TArmyStack* enemyStack, short battleContext);

  void EndBattlePhase();

  // Select the first matching unit and return how many remain in the other state.
  // ABI: thiscall on the singleton; the bodies ignore `this`.
  short SelectUnitType(short categoryId, short tileIndex);
  short DeSelectUnitType(short categoryId, short tileIndex);

  // Whether the province holds an idle military unit.
  bool AnySelectableUnits(short regionId);

  int GetSelectedForceSize();

  // Selects a province (-1 clears), resetting its units' order modes.
  void SetSelectedProvince(short cityRecordIndex);
  void ResetCycle(short nationId);
  short Cycle(short nationId);

  // ABI: thiscall on the singleton; the bodies ignore `this`.
  unsigned short LookupMapCursorTokenByStateIndex(short tileIndex, short mode);
  unsigned short GetCivilianCursor(short tileIndex, short mode);

  // Civilian counterpart of ComputeMapCursorStateIndex.
  int GetTileSelection(short tileIndex, short mode);
  bool CanOrderToTile(short cityRecordIndex);
  void MarchSelectedArmies(short tileIndex);
  void StartTacticalBattle(TArmyStack* ourStack, TArmyStack* enemyStack, int ownerNationCodeInt);
  void ShowSpyReport(int cityRecordIndex);

  bool GenerateSpyReport(int cityRecordIndex, CString& outDefenderSummary,
                         CString& outGarrisonSummary);

  void CheckForDrownedUnits(char nationId, int cityIndex, struct MapOrderBattleSnapshot* snapshot);

  bool HasBattlesToReport() const;

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
