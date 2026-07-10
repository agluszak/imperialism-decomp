#include "game/TTacticalBattle.h"

#include "game/CIterator.h"
#include "game/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/TMilitaryUnit.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TTacticalBattleView.h"
#include "game/TTacticalPlayer.h"
#include "game/global_data_tables.h"

undefined TTacticalBattle::OrphanRetStub_0059f710() {
  return 0;
}

undefined TTacticalBattle::CreateTTacticalBattleInstance() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0059f6d0
// TTacticalBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059f750
// TTacticalBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalBattle, TObject)

// Body assignments (not a member-init list) reproduce the original store order
// +4, +8, +0x24, +0x1c, +0x34, +0x74, +0x20, which does not follow declaration order.
// FUNCTION: IMPERIALISM 0x0059f770
TTacticalBattle::TTacticalBattle() {
  tileGrid4 = 0;
  battleView8 = 0;
  field24 = 0;
  selectedUnit1c = 0;
  field34 = 0;
  field74 = 0;
  recordList20 = 0;
}

// SYNTHETIC: IMPERIALISM 0x0059f7a0
// TTacticalBattle::`scalar deleting destructor'
TTacticalBattle::~TTacticalBattle() {}

void TTacticalBattle::Free() {}

// FUNCTION: IMPERIALISM 0x0059f890
void TTacticalBattle::BuildTacticalBattleStateFromBothSides(TTacticalPlayer* ourPlayer,
                                                            TTacticalPlayer* enemyPlayer) {
  // TODO: port body @ 0x59f890 (Mac oracle: InitTacticalBattle; sets tacticalPlayer14/18,
  // allocates tileGrid4, publishes this to g_pActiveTacticalBattle).
  (void)ourPlayer;
  (void)enemyPlayer;
}

undefined TTacticalBattle::ComputeTacticalReachableTileCostsByUnitCategory(int param_1) {
  return 0;
}

undefined TTacticalBattle::PropagateTileAccessibilityStrengthLevels(char* param_1) {
  return 0;
}

undefined TTacticalBattle::WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400(
    undefined4 param_1, int param_2, char param_3) {
  return 0;
}

undefined
TTacticalBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(int param_1,
                                                                              undefined4 param_2) {
  return 0;
}

undefined TTacticalBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(int param_1) {
  return 0;
}

undefined TTacticalBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(int* param_1,
                                                                               int param_2) {
  return 0;
}

undefined TTacticalBattle::OrphanCallChain_C4_I30_005a2700(int param_1) {
  return 0;
}

undefined TTacticalBattle::MarkTacticalTileStateQueuedAndMaybeDispatchPacket(int* param_1,
                                                                             int param_2) {
  return 0;
}

undefined TTacticalBattle::AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(int param_1) {
  return 0;
}

undefined TTacticalBattle::ClearTacticalTileStateRunByStride(int param_1) {
  return 0;
}

undefined TTacticalBattle::ExecuteTacticalMineActionAndQueuePacket(int param_1, int param_2) {
  return 0;
}

undefined TTacticalBattle::ExecuteTacticalDigActionAndConsumeUnitActionPoints(int* param_1,
                                                                              undefined4 param_2) {
  return 0;
}

undefined TTacticalBattle::ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059fc20
undefined TTacticalBattle::StartBattle() {
  return tacticalPlayer18->StartBattle();
}

// Selection/UI helpers dispatched by the command family; bodies not yet ported.

// FUNCTION: IMPERIALISM 0x0059fe40
void TTacticalBattle::ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit) {
  // TODO: port body @ 0x59fe40 (sets selectedUnit1c and refreshes the selection UI).
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x005a0420
void TTacticalBattle::ComputeHexNeighborTileIndices_005A0420(int tileIndex,
                                                             int* outNeighborTiles6) {
  // TODO: port body @ 0x5a0420 (six hex-neighbor tile indices; -1 = off-grid).
  (void)tileIndex;
  (void)outNeighborTiles6;
}

// Tactical command family: each handler echoes the command to multiplayer when it
// originates locally (remoteFlag == 0), then applies it to the battle state. The
// 0x545940 turn-event dispatcher re-enters these with remoteFlag = 1.

// Selects a tactical unit: echoes a 'sele' command in multiplayer, flips the current
// side to match the unit, refreshes the action toolbar + old/new selection rects,
// refills the unit's action points, and applies the selection state.
// FUNCTION: IMPERIALISM 0x005a1010
void TTacticalBattle::SetCurrentTacticalUnitSelection(TTacticalUnit* unit, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x73656c65 /* 'sele' */, unit, 0, 0);
    }
  }
  if (unit->side20 != currentSideC) {
    currentSideC = currentSideC == 0;
  }
  if (battleView8 != 0) {
    battleView8->UpdateTacticalActionControlBitmapForCurrentUnit(static_cast<char>(unit->side20));
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(selectedUnit1c);
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  unit->actionPoints28 = unit->GetBaseActionPoints();
  unit->selectedFlag18 = 1;
  ApplyTacticalDoneSelectionAndRefreshUi(unit);
}

// Moves a unit from one battle-grid tile to another: multiplayer 'move' echo, clear the
// source tile's occupant, optionally animate (suppressed when field4c == 7), re-anchor
// the unit on the destination tile, and refresh the affected view rects/marker.
// FUNCTION: IMPERIALISM 0x005a1910
void TTacticalBattle::MoveTacticalUnitBetweenTiles(TTacticalUnit* unit, int fromTileIndex,
                                                   int toTileIndex, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x6d6f7665 /* 'move' */, unit, fromTileIndex,
                                                  toTileIndex);
    }
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  tileGrid4[fromTileIndex].occupant4 = 0;
  if (battleView8 != 0) {
    battleView8->TriggerTacticalUiUpdate2711();
  }
  if (field4c != 7) {
    if (battleView8 != 0) {
      battleView8->AnimateTacticalUnitMoveBetweenTiles(unit, fromTileIndex, toTileIndex);
    }
  }
  unit->tileIndex8 = toTileIndex;
  tileGrid4[toTileIndex].occupant4 = unit;
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalHexTileRect(toTileIndex);
  }
  if (battleView8 != 0) {
    battleView8->SpawnTacticalUiMarkerAtUnitTile();
  }
}

// Resolves a 'fire' action: multiplayer echo, virtual damage application on the target,
// camera snap + per-unit-type fire sfx + tile hit effect (big effect 0xf6e for category
// 6/7 or unit type 0x15, small 0xf78 otherwise), removal of a destroyed target from the
// grid, and end-of-battle evaluation.
// FUNCTION: IMPERIALISM 0x005a24a0
void TTacticalBattle::ApplyTacticalActionEffectsAndMaybeRemoveUnit(TTacticalUnit* attackerUnit,
                                                                   TTacticalUnit* targetUnit,
                                                                   int targetTileIndex, int damageA,
                                                                   int damageB, char effectCode2C,
                                                                   char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalFireCommandPacket(0x66697265 /* 'fire' */, attackerUnit,
                                                      targetUnit, damageA, damageB, effectCode2C);
    }
  }
  targetUnit->ApplyTacticalDamage(damageA, damageB);
  if (battleView8 != 0) {
    battleView8->CenterViewportAroundGridIndexAndSnap(targetTileIndex);
    short sfxToken = g_awTacticalFireSfxTokenByUnitType[attackerUnit->unitTypeC];
    g_pSfxPlaybackSystem->PlaySoundEffect(sfxToken, 0, 1);
    short categoryCode = g_awTacticalUnitCategoryCodeBySlot[attackerUnit->unitTypeC];
    if (categoryCode == 6 || categoryCode == 7 || attackerUnit->unitTypeC == 0x15) {
      if (battleView8 != 0) {
        // TODO(verify): 0xf6e/6 vs 0xf78/3 assumed effect-id + frame-count pair.
        battleView8->PlayTacticalTileEffect(targetTileIndex, 0xf6e, 6);
      }
    } else {
      if (battleView8 != 0) {
        battleView8->PlayTacticalTileEffect(targetTileIndex, 0xf78, 3);
      }
    }
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(targetTileIndex);
    }
  }
  if (targetUnit->state1c == 3) {
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalHexTileRect(targetUnit->tileIndex8);
    }
    if (battleView8 != 0) {
      battleView8->InvalidateTacticalUnitTileRect(targetUnit);
    }
    tileGrid4[targetUnit->tileIndex8].occupant4 = 0;
    targetUnit->tileIndex8 = -1;
  }
  attackerUnit->selectedFlag18 = 0;
  EvaluateTacticalSideStateAndShowBattleSummaryDialog();
}

// FUNCTION: IMPERIALISM 0x005a2750
void TTacticalBattle::EvaluateTacticalSideStateAndShowBattleSummaryDialog() {
  // TODO: port body @ 0x5a2750.
}

// 'mine' command: multiplayer echo (no unit), consume from the side resource pool for
// the tile, then mining sfx + tile effect when a view is attached.
// FUNCTION: IMPERIALISM 0x005a35a0
void TTacticalBattle::HandleTacticalCommandTag_mine(int tileIndex, int amount, char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x6d696e65 /* 'mine' */, 0, tileIndex, amount);
    }
  }
  ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty(tileIndex, amount);
  if (battleView8 != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3a9d, 0, 1);
    battleView8->PlayTacticalTileEffect(tileIndex, 0xf98, 6);
  }
}

// 'digg' command: digs a trench link between the unit's tile and an adjacent target
// tile -- finds the hex direction of the target among the unit tile's six neighbors,
// then sets the paired direction bits (and the 0x80 first-dig / 0x40 linked state
// bits) in both tiles' trench masks.
// FUNCTION: IMPERIALISM 0x005a36d0
void TTacticalBattle::HandleTacticalCommandTag_digg(TTacticalUnit* unit, int targetTileIndex,
                                                    char remoteFlag) {
  int neighborTiles[6];
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x64696767 /* 'digg' */, unit, targetTileIndex,
                                                  0);
    }
  }
  int unitTileIndex = unit->tileIndex8;
  ComputeHexNeighborTileIndices_005A0420(unitTileIndex, neighborTiles);
  int direction = 0;
  int* neighborCursor = neighborTiles;
  do {
    if (*neighborCursor == targetTileIndex) {
      break;
    }
    ++direction;
    ++neighborCursor;
  } while (direction < 6);
  unsigned char srcMask = tileGrid4[unitTileIndex].trenchMask10;
  if (srcMask == 0) {
    tileGrid4[unitTileIndex].trenchMask10 = 0x80;
  } else {
    tileGrid4[unitTileIndex].trenchMask10 = srcMask & 0x7f;
    tileGrid4[unitTileIndex].trenchMask10 |= 0x40;
  }
  tileGrid4[unitTileIndex].trenchMask10 |= static_cast<unsigned char>(1 << direction);
  direction += 3;
  if (direction > 5) {
    direction -= 6;
  }
  unsigned char dstMask = tileGrid4[targetTileIndex].trenchMask10;
  if (dstMask != 0) {
    tileGrid4[targetTileIndex].trenchMask10 = dstMask & 0x7f;
    tileGrid4[targetTileIndex].trenchMask10 |= 0x40;
  }
  tileGrid4[targetTileIndex].trenchMask10 |= static_cast<unsigned char>(1 << direction);
}

// 'raly' command: multiplayer echo, sets the unit's state (rallying a broken unit) and
// restores morale to min(newMorale, strength), then refreshes the unit rect and plays
// the rally sfx.
// FUNCTION: IMPERIALISM 0x005a38e0
void TTacticalBattle::HandleTacticalCommandTag_raly(TArmyTacUnit* unit, int newMorale, int newState,
                                                    char remoteFlag) {
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x72616c79 /* 'raly' */, unit, newMorale,
                                                  newState);
    }
  }
  int strength = unit->strength4;
  unit->state1c = newState;
  if (newMorale > strength) {
    unit->morale34 = strength;
  } else {
    unit->morale34 = newMorale;
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
  if (battleView8 != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aae, 0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005a3c20
void TTacticalBattle::ConsumeTacticalSideResourcePoolAndInvalidateIfEmpty(int tileIndex,
                                                                          int consumeAmount) {
  // TODO: port body @ 0x5a3c20.
  (void)tileIndex;
  (void)consumeAmount;
}

// 'depl' command: places a unit on a battle-grid tile during deployment; for
// trench-capable units (flag3c) outside the fortLevel49 mode it marks the tile deployed
// and invalidates the six neighbor tiles, then refreshes the unit rect.
// FUNCTION: IMPERIALISM 0x005a4370
void TTacticalBattle::HandleTacticalCommandTag_depl(TArmyTacUnit* unit, int tileIndex,
                                                    char remoteFlag) {
  int neighborTiles[6];
  if (remoteFlag == 0) {
    unsigned char multiplayerActive = g_pSimMgr->field44 != 0;
    if (multiplayerActive != 0) {
      g_pGameFlowState->EmitTacticalCommandPacket(0x6465706c /* 'depl' */, unit, tileIndex, 0);
    }
  }
  unit->tileIndex8 = tileIndex;
  tileGrid4[tileIndex].occupant4 = unit;
  if (unit->flag3c != 0 && fortLevel49 == 0) {
    tileGrid4[tileIndex].deployMark8 = 1;
    if (battleView8 != 0) {
      ComputeHexNeighborTileIndices_005A0420(tileIndex, neighborTiles);
      int* neighborCursor = neighborTiles;
      int remaining = 6;
      do {
        if (*neighborCursor != -1) {
          battleView8->InvalidateTacticalHexTileRect(*neighborCursor);
        }
        ++neighborCursor;
        --remaining;
      } while (remaining != 0);
    }
  }
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }
}

// Walks recordList20 for the tactical unit whose source army unit's TUnit::field_20 id
// matches nestedId; 0 when nestedId is 0 or nothing matches.
// FUNCTION: IMPERIALISM 0x005a53e0
TArmyTacUnit* TTacticalBattle::SeekLinkedListCursorByNestedId(int nestedId) {
  if (nestedId == 0) {
    return 0;
  }
  CIterator unitIter(recordList20);
  for (TArmyTacUnit* unit = static_cast<TArmyTacUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TArmyTacUnit*>(unitIter.Advance())) {
    int foundId;
    if (unit != 0 && unit->sourceUnit38 != 0) {
      foundId = unit->sourceUnit38->field_20;
    } else {
      foundId = 0;
    }
    if (nestedId == foundId) {
      return unit;
    }
  }
  return 0;
}
