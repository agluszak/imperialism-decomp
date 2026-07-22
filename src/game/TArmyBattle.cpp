#include "game/TArmyBattle.h"

#include <stdio.h>
#include <stdlib.h>

#include "game/CFile_Virtuals.h"
#include "game/CIterator.h"
#include "game/CString.h"
#include "game/TAssetMgr.h"
#include "game/TArmyMgr.h"
#include "game/TArmyPlayer.h"
#include "game/TArmyStack.h"
#include "game/TArmyTacUnit.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TList.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TTacticalBattleView.h"
#include "game/TTacticalToolbar.h"
#include "game/ui_control_tags.h"
#include "game/TStream.h"
#include "game/TTacArmyView.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x004a5c50
// TArmyBattle::`scalar deleting destructor'
TArmyBattle::~TArmyBattle() {}
// SYNTHETIC: IMPERIALISM 0x005a4710
// TArmyBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a4750
// TArmyBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyBattle, TTacticalBattle)

// Not the constructor: neither original construction site calls this (both inline the
// ctor as base-ctor + vtable install), and this body neither installs a vtable nor calls
// the base ctor. It is the separate post-construction list allocator, reached via the
// 0x5a4770 jump island from the TArmyMgr battle-setup site.
// FUNCTION: IMPERIALISM 0x0059f7f0
void TArmyBattle::AllocateRecordList() {
  recordList20 = new TList();
}

// FUNCTION: IMPERIALISM 0x005a4790
void TArmyBattle::InitializeBattleSetupAndMaybeDispatchTurnEventED8(TArmyStack* ourStack,
                                                                    TArmyStack* enemyStack,
                                                                    int compositionClass,
                                                                    int fortLevel,
                                                                    int battleSiteIndex) {
  // Fixed tactical battle grid: 435 tiles (0x1b3), stride 29 (0x1d).
  tacticalTileCount3c = 0x1b3;
  tacticalTileStride40 = 0x1d;
  // AI/watch flags for each side (TGreatPower +0xa0), only when preference slot 0 is
  // set and no multiplayer session mode is active.
  unsigned char ourSideWatchFlag = 0;
  unsigned char enemySideWatchFlag = 0;
  if (g_pSimMgr->preferenceValues[0] != 0) {
    unsigned char sessionModeActive = g_pSimMgr->multiplayerSessionRole != 0;
    if (sessionModeActive == 0) {
      ourSideWatchFlag = g_apNationStates[ourStack->categoryFlag8]->diplomacyEligibilityA0;
      if (enemyStack->categoryFlag8 < 7) {
        enemySideWatchFlag = g_apNationStates[enemyStack->categoryFlag8]->diplomacyEligibilityA0;
      } else {
        enemySideWatchFlag = 0; // explicit redundant store present in the original
      }
    }
  }

  TArmyPlayer* ourPlayer = new TArmyPlayer();
  ourPlayer->InitializeTacticalSideFromArmyUnitList(ourStack, 1, ourSideWatchFlag,
                                                    ourStack->categoryFlag8);
  TArmyPlayer* enemyPlayer = new TArmyPlayer();
  enemyPlayer->InitializeTacticalSideFromArmyUnitList(enemyStack, 0, enemySideWatchFlag,
                                                      enemyStack->categoryFlag8);
  BuildTacticalBattleStateFromBothSides(ourPlayer, enemyPlayer);

  battleSiteIndex38 = battleSiteIndex;
  LoadBattleSetupTabDataByIndex(compositionClass, fortLevel);
  compositionClass50 = compositionClass;
  fortLevel49 = static_cast<char>(fortLevel);

  // Show the live tactical-battle view when forced globally or either side is watched.
  if (g_nForceTacticalBattleViewFlag_006A4758 != 0 || enemySideWatchFlag != 0 ||
      ourSideWatchFlag != 0) {
    g_nTurnCooldownDeferCounter006A43C4 = 0;
    g_pSfxPlaybackSystem->RequestAudioPresetChangeWithDeferredApply(
        static_cast<int>(rand()) % 3 + 6, 0); // battle cue 6..8
    g_pUiRuntimeContext->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTacticalView), 0);
    TTacArmyView* battleView = static_cast<TTacArmyView*>(
        g_pDisplayMgr->activeDialog->ResolveControlByTag(0x444c4f47 /* 'DLOG' */));
    battleView->AssertValid();
    battleView8 = battleView;
    battleView->ConstructTTacArmyViewBaseState(compositionClass, this);
  }
}

// FUNCTION: IMPERIALISM 0x005a4990
void TArmyBattle::ReadFrom(TStream* stream) {
  stream->ReadBytes(&currentSideC, 4);
  stream->ReadBytes(&battleLive10, 4);
  // Per-side stack identity triplets (index into g_apNationStates, owner nation code,
  // originating tile), written by WriteTo from each player's armyStack28.
  int ourNationIndex;
  int ourNationCode;
  int ourTileIndex;
  int enemyNationIndex;
  int enemyNationCode;
  int enemyTileIndex;
  stream->ReadBytes(&ourNationIndex, 4);
  stream->ReadBytes(&ourNationCode, 4);
  stream->ReadBytes(&ourTileIndex, 4);
  stream->ReadBytes(&enemyNationIndex, 4);
  stream->ReadBytes(&enemyNationCode, 4);
  stream->ReadBytes(&enemyTileIndex, 4);

  // Only the low word is read from the stream; the loop tests the word and decrements
  // the full dword, matching the original codegen.
  int unitRecordCount;
  stream->ReadBytes(&unitRecordCount, 2);
  while (static_cast<short>(unitRecordCount--) != 0) {
    int unitId;
    stream->ReadBytes(&unitId, 4);
    TMilitaryUnit* sourceUnit = TMilitaryUnit::FindUnitByUID(unitId);
    TArmyTacUnit* record = new TArmyTacUnit();
    // Field-fill mirrors the TArmyTacUnit base-state init (0x5a5f20) exactly (same
    // store order) -- the original duplicated this init here.
    record->unitTypeC = sourceUnit->orderType;
    record->tileIndex8 = -2;
    record->selectedFlag18 = 0;
    record->state1c = 0;
    record->actionPoints28 = record->GetBaseActionPoints();
    record->aiStateCode2c = 0;
    record->attackTarget30 = NULL;
    record->strength4 = sourceUnit->field_34;
    record->morale34 = sourceUnit->field_34;
    record->qualityLevel10 = static_cast<short>(sourceUnit->field_38 / 100);
    record->ownerNationIndex14 = sourceUnit->field_18;
    record->sapTargetTileIndex40 = -1;
    record->sourceUnit38 = sourceUnit;
    unsigned char deployedCategory0Flag;
    if (sourceUnit->unitOrder == 2 &&
        g_anUnitTypeCombatCategoryByType00669858[record->unitTypeC] == 0) {
      deployedCategory0Flag = 1;
    } else {
      deployedCategory0Flag = 0;
    }
    record->flag3c = deployedCategory0Flag;
    stream->ReadBytes(&record->side20, 4);
    stream->ReadBytes(&record->field24, 2);
    recordList20->AddTail(record);
  }

  // Re-link the selected/linked unit record by its source unit id.
  int linkedUnitId;
  stream->ReadBytes(&linkedUnitId, 4);
  TArmyTacUnit* linkedRecord = 0;
  if (linkedUnitId != 0) {
    CIterator linkIter(recordList20);
    for (TArmyTacUnit* candidate = static_cast<TArmyTacUnit*>(linkIter.Reset()); linkIter.More();
         candidate = static_cast<TArmyTacUnit*>(linkIter.Advance())) {
      int candidateUnitId;
      if (candidate != 0 && candidate->sourceUnit38 != 0) {
        candidateUnitId = candidate->sourceUnit38->field_20;
      } else {
        candidateUnitId = 0;
      }
      if (candidateUnitId == linkedUnitId) {
        linkedRecord = candidate;
        break;
      }
    }
  }
  selectedUnit1c = linkedRecord;

  stream->ReadBytes(&battleSiteIndex38, 4);
  stream->ReadBytes(&battleOutcomeCode44, 4);
  stream->ReadBytes(&fortLevel49, 1);
  stream->ReadBytes(&currentTacticalActionCode4c, 4);
  stream->ReadBytes(&compositionClass50, 4);

  // Rebuild the two combatant stacks and re-add every source unit to its side.
  TArmyStack* ourBattleStack = new TArmyStack();
  ourBattleStack->InitializeSideAndTile(static_cast<char>(ourNationIndex),
                                        static_cast<short>(ourNationCode),
                                        static_cast<short>(ourTileIndex));
  TArmyStack* enemyBattleStack = new TArmyStack();
  enemyBattleStack->InitializeSideAndTile(static_cast<char>(enemyNationIndex),
                                          static_cast<short>(enemyNationCode),
                                          static_cast<short>(enemyTileIndex));
  CIterator recordIter(recordList20);
  for (TArmyTacUnit* deployRecord = static_cast<TArmyTacUnit*>(recordIter.Reset());
       recordIter.More(); deployRecord = static_cast<TArmyTacUnit*>(recordIter.Advance())) {
    TArmyStack* targetStack;
    if (deployRecord->ownerNationIndex14 == ourNationIndex) {
      targetStack = ourBattleStack;
    } else {
      targetStack = enemyBattleStack;
    }
    targetStack->AddUnitToChainHead(deployRecord->sourceUnit38);
  }

  InitializeBattleSetupAndMaybeDispatchTurnEventED8(
      ourBattleStack, enemyBattleStack, compositionClass50, fortLevel49, battleSiteIndex38);
}

// FUNCTION: IMPERIALISM 0x005a4da0
void TArmyBattle::WriteTo(TStream* stream) {
  stream->WriteBytesSlot78(&currentSideC, 4);
  stream->WriteBytesSlot78(&battleLive10, 4);

  TArmyPlayer* ourPlayer = static_cast<TArmyPlayer*>(tacticalPlayer14);
  ourPlayer->AssertValid();
  int ourNationIndex = ourPlayer->armyStack28->categoryFlag8;
  stream->WriteBytesSlot78(&ourNationIndex, 4);
  int ourNationCode = ourPlayer->armyStack28->ownerNationCodeE;
  stream->WriteBytesSlot78(&ourNationCode, 4);
  int ourTileIndex = ourPlayer->armyStack28->tileIndex10;
  stream->WriteBytesSlot78(&ourTileIndex, 4);

  TArmyPlayer* enemyPlayer = static_cast<TArmyPlayer*>(tacticalPlayer18);
  enemyPlayer->AssertValid();
  int enemyNationIndex = enemyPlayer->armyStack28->categoryFlag8;
  stream->WriteBytesSlot78(&enemyNationIndex, 4);
  int enemyNationCode = enemyPlayer->armyStack28->ownerNationCodeE;
  stream->WriteBytesSlot78(&enemyNationCode, 4);
  int enemyTileIndex = enemyPlayer->armyStack28->tileIndex10;
  stream->WriteBytesSlot78(&enemyTileIndex, 4);

  int unitRecordCount = recordList20->GetCount();
  stream->WriteBytesSlot78(&unitRecordCount, 2);
  CIterator recordIter(recordList20);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(recordIter.Reset()); recordIter.More();
       record = static_cast<TArmyTacUnit*>(recordIter.Advance())) {
    int recordUnitId;
    if (record != 0 && record->sourceUnit38 != 0) {
      recordUnitId = record->sourceUnit38->field_20;
    } else {
      recordUnitId = 0;
    }
    stream->WriteBytesSlot78(&recordUnitId, 4);
    stream->WriteBytesSlot78(&record->side20, 4);
    stream->WriteBytesSlot78(&record->field24, 2);
  }

  TArmyTacUnit* linked = static_cast<TArmyTacUnit*>(selectedUnit1c);
  int linkedUnitId;
  if (linked != 0 && linked->sourceUnit38 != 0) {
    linkedUnitId = linked->sourceUnit38->field_20;
  } else {
    linkedUnitId = 0;
  }
  stream->WriteBytesSlot78(&linkedUnitId, 4);

  stream->WriteBytesSlot78(&battleSiteIndex38, 4);
  stream->WriteBytesSlot78(&battleOutcomeCode44, 4);
  stream->WriteBytesSlot78(&fortLevel49, 1);
  stream->WriteBytesSlot78(&currentTacticalActionCode4c, 4);
  stream->WriteBytesSlot78(&compositionClass50, 4);
}

// FUNCTION: IMPERIALISM 0x005a4fc0
void TArmyBattle::LoadBattleSetupTabDataByIndex(int compositionClass, int fortLevel) {
  CString tabFileName;
  // Battle-setup terrain layout file, 1-based composition class ("data/%03d.tab").
  // Layout is 15 rows x 29 cols + one newline byte per row.
  char nameBuf[64];
  int byteCount = tacticalTileCount3c + 0xf; // 0x1b3 tiles + 15 row-terminator bytes
  sprintf(nameBuf, g_szBattleSetupTabPathFormat, compositionClass + 1);
  tabFileName = CString(nameBuf);

  char* tabData = new char[byteCount];
  CFile_Virtuals* stream = g_pUiViewManager->LoadTableResourceStreamByName(tabFileName);
  g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, tabData, &byteCount);
  g_pUiViewManager->ReleaseResourceStreamIfNotNull(stream);

  // Parse the character grid into the tile records. Each source row is 0x1d chars +
  // 1 terminator; the first (0x1d - battlefieldColumnCount34) chars of each row are margin (skipped
  // without consuming a grid cell), so battlefieldColumnCount34 cells are filled per row and the record
  // cursor then skips the remaining (0x1d - battlefieldColumnCount34) cells of that grid row.
  TacticalTileRecord* record = tileGrid4;
  char* src = tabData;
  for (int rowsLeft = 0xf; rowsLeft != 0; --rowsLeft) {
    for (int col = 0; col < 0x1d; ++col) {
      if (col < 0x1d - battlefieldColumnCount34) {
        ++src; // margin char: no grid cell consumed
        continue;
      }
      if (fortLevel > 1 && col > 0x17) {
        record->terrainType0 = 0; // fort present (level >= 2): blank the last 5 columns
      } else {
        record->terrainType0 = *src; // movsx: signed char -> int
      }
      ++src;
      record->occupant4 = 0;
      record->deployMark8 = 0;
      record->mineRunStateC = -1;
      record->trenchMask10 = 0;
      ++record;
    }
    ++src;                                     // skip the row terminator byte
    record += 0x1d - battlefieldColumnCount34; // skip the grid cells this row didn't cover
  }

  delete[] tabData;

  if (fortLevel != 0) {
    // Mark the fort column (tile battlefieldColumnCount34 - 6, then every row below at stride 0x1d)
    // with the fort level in deployMark8.
    for (int tile = battlefieldColumnCount34 - 6; tile < 0x1b3; tile += 0x1d) {
      tileGrid4[tile].deployMark8 = fortLevel;
    }
    // Seed the 8 fort-strength slots from the per-level table (load kept inside the
    // loop, matching the original).
    for (int slot = 0; slot < 8; ++slot) {
      fortStrengthPoints54[slot] = g_anFortStrengthPointsByFortLevel[fortLevel];
    }
  }
}

// Real deployment placement (slot 0x0c override): validates the tile against the
// current side's deployment zone (same guard band as ApplyGridColumnSelectionGuard),
// applies/echoes the 'depl' command, advances the done-selection to the side's next
// undeployed unit, resets the move-cost plane, and either fires the ready handler when
// the side has fully deployed or refreshes the 'tool' toolbar's current-unit control.
// FUNCTION: IMPERIALISM 0x005a51e0
void TArmyBattle::DeployTacticalUnitToTile(TTacticalUnit* unit, TacticalTileIndex tileIndex) {
  unit->AssertValid();
  int column = tileIndex % 29;
  if (tileIndex < 29) {
    return;
  }
  TacticalTileRecord* record = &tileGrid4[tileIndex];
  if (record->terrainType0 == 4) {
    return;
  }
  if (record->occupant4 != 0) {
    return;
  }
  if (currentSideC == 0) {
    if (column < 3) {
      return;
    }
    if (column > 5) {
      return;
    }
  } else {
    if (column > battlefieldColumnCount34 - 3) {
      return;
    }
    if (column < battlefieldColumnCount34 - 5) {
      return;
    }
  }
  HandleTacticalCommandTag_depl(static_cast<TArmyTacUnit*>(unit), tileIndex, 0);
  TTacticalPlayer* sidePlayer = (currentSideC == 0) ? tacticalPlayer14 : tacticalPlayer18;
  ApplyTacticalDoneSelectionAndRefreshUi(sidePlayer->SelectNextTacticalUnitForDoneCommand());
  for (int planeIndex = 0; planeIndex < tacticalTileCount3c; ++planeIndex) {
    tileMoveCostArray24[planeIndex] = -1;
  }
  TTacticalPlayer* readyPlayer = (currentSideC == 0) ? tacticalPlayer14 : tacticalPlayer18;
  if (readyPlayer->sideReadyFlag10 != 0) {
    HandleTacticalCommandTag_retr(); // side fully deployed -> hand the round over
    return;
  }
  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(0x746f6f6c /* 'tool' */));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit1c);
  }
}

// FUNCTION: IMPERIALISM 0x005a5320
undefined TArmyBattle::FinalizeTacticalBattleOutcome(int sideWonFlag) {
  battleOutcomeCode44 = 1;
  tacticalPlayer14->AssertValid();
  tacticalPlayer18->AssertValid();
  g_pSfxPlaybackSystem->StopCdAudioPlayback(0);

  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(0x746f6f6c /* 'tool' */));
    toolbar->AssertValid();
    toolbar->TacticalToolbarSlot74(0);
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(0);
  }

  g_pMapContextActionManager->ApplyPostBattleStackOutcomeAndGrowUnitMeters(
      static_cast<TArmyPlayer*>(tacticalPlayer14)->armyStack28,
      static_cast<TArmyPlayer*>(tacticalPlayer18)->armyStack28, sideWonFlag, battleSiteIndex38);
  return 0;
}
