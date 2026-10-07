#include "game/tactical/TArmyBattle.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include <stdio.h>
#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/assets/TAssetMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/tactical/TArmyPlayer.h"
#include "game/military/TArmyStack.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/TList.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/tactical/TTacticalBattleView.h"
#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/core/TStream.h"
#include "game/tactical_ui/TTacArmyView.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/globals/ui_widgets_globals.h"

IMPLEMENT_DYNCREATE(TArmyBattle, TTacticalBattle)

// FUNCTION: IMPERIALISM 0x0059f7f0
void TArmyBattle::AllocateRecordList() {
  recordList = new TList();
}

// FUNCTION: IMPERIALISM 0x0059fc40
void TArmyBattle::GetBattlefieldColumns() {
  int maxRange = 0;
  CIterator rangeIter(recordList);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(rangeIter.Reset()); rangeIter.More();
       record = static_cast<TArmyTacUnit*>(rangeIter.Advance())) {
    if (maxRange < record->GetUnitRange()) {
      maxRange = record->GetUnitRange();
    }
  }
  battlefieldColumnCount = maxRange + 0xb;
}

// FUNCTION: IMPERIALISM 0x005a4790
void TArmyBattle::SetUpBattle(TArmyStack* ourStack, TArmyStack* enemyStack, int compositionClass,
                              int fortLevel, int battleSiteIndex) {
  // Fixed tactical battle grid: 435 tiles (0x1b3), stride 29 (0x1d).
  tacticalTileCount = 0x1b3;
  tacticalTileStride = 0x1d;
  unsigned char ourSideWatchFlag = 0;
  unsigned char enemySideWatchFlag = 0;
  if (g_pSimMgr->preferenceValues[0] != 0) {
    bool sessionModeActive = g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone;
    if (!sessionModeActive) {
      ourSideWatchFlag = g_apNationStates[ourStack->categoryFlag]->diplomacyEligibility;
      if (enemyStack->categoryFlag < 7) {
        enemySideWatchFlag = g_apNationStates[enemyStack->categoryFlag]->diplomacyEligibility;
      } else {
        enemySideWatchFlag = 0; // explicit redundant store present in the original
      }
    }
  }

  TArmyPlayer* ourPlayer = new TArmyPlayer();
  ourPlayer->IArmyPlayer(ourStack, true, ourSideWatchFlag, ourStack->categoryFlag);
  TArmyPlayer* enemyPlayer = new TArmyPlayer();
  enemyPlayer->IArmyPlayer(enemyStack, false, enemySideWatchFlag, enemyStack->categoryFlag);
  InitTacticalBattle(ourPlayer, enemyPlayer);

  this->battleSiteIndex = battleSiteIndex;
  LoadMap(compositionClass, fortLevel);
  this->compositionClass = compositionClass;
  this->fortLevel = static_cast<char>(fortLevel);

  // Show the live tactical-battle view when forced globally or either side is watched.
  if (g_nForceTacticalBattleViewFlag || enemySideWatchFlag != 0 || ourSideWatchFlag != 0) {
    g_nTurnCooldownDeferCounter = 0;
    g_pSfxPlaybackSystem->RequestMusicChange(rand() % 3 + 6,
                                             false); // battle cue 6..8
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTacticalView), 0);
    TTacArmyView* battleView =
        static_cast<TTacArmyView*>(g_pDisplayMgr->activeDialog->FindSubView(kControlTagDialog));
    battleView->AssertValid();
    this->battleView = battleView;
    battleView->StuffValues(compositionClass, this);
  }
}

// FUNCTION: IMPERIALISM 0x005a4990
void TArmyBattle::ReadFrom(TStream* stream) {
  stream->ReadBytes(&currentSide, 4);
  stream->ReadBytes(&battleLive, 4);
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

  unsigned short unitRecordCount;
  stream->ReadBytes(&unitRecordCount, sizeof(unitRecordCount));
  for (int unitIndex = 0; unitIndex < unitRecordCount; ++unitIndex) {
    int unitId;
    stream->ReadBytes(&unitId, 4);
    TMilitaryUnit* sourceUnit = TMilitaryUnit::FindUnitByUID(unitId);
    TArmyTacUnit* record = new TArmyTacUnit();
    record->IArmyTacUnit(sourceUnit);
    stream->ReadBytes(&record->side, 4);
    stream->ReadBytes(&record->field24, 2);
    recordList->AddTail(record);
  }

  // Re-link the selected/linked unit record by its source unit id.
  int linkedUnitId;
  stream->ReadBytes(&linkedUnitId, 4);
  TArmyTacUnit* linkedRecord = 0;
  if (linkedUnitId != 0) {
    CIterator linkIter(recordList);
    for (TArmyTacUnit* candidate = static_cast<TArmyTacUnit*>(linkIter.Reset()); linkIter.More();
         candidate = static_cast<TArmyTacUnit*>(linkIter.Advance())) {
      int candidateUnitId = candidate != 0 ? candidate->GetUID() : 0;
      if (candidateUnitId == linkedUnitId) {
        linkedRecord = candidate;
        break;
      }
    }
  }
  selectedUnit = linkedRecord;

  stream->ReadBytes(&battleSiteIndex, 4);
  stream->ReadBytes(&battleOutcome, 4);
  stream->ReadBytes(&fortLevel, 1);
  stream->ReadBytes(&currentTacticalActionCode, 4);
  stream->ReadBytes(&compositionClass, 4);

  // Rebuild the two combatant stacks and re-add every source unit to its side.
  TArmyStack* ourBattleStack = new TArmyStack();
  ourBattleStack->IArmyStack(static_cast<char>(ourNationIndex), static_cast<short>(ourNationCode),
                             static_cast<short>(ourTileIndex));
  TArmyStack* enemyBattleStack = new TArmyStack();
  enemyBattleStack->IArmyStack(static_cast<char>(enemyNationIndex),
                               static_cast<short>(enemyNationCode),
                               static_cast<short>(enemyTileIndex));
  CIterator recordIter(recordList);
  for (TArmyTacUnit* deployRecord = static_cast<TArmyTacUnit*>(recordIter.Reset());
       recordIter.More(); deployRecord = static_cast<TArmyTacUnit*>(recordIter.Advance())) {
    TArmyStack* targetStack;
    if (deployRecord->ownerNationIndex == ourNationIndex) {
      targetStack = ourBattleStack;
    } else {
      targetStack = enemyBattleStack;
    }
    targetStack->AddUnit(deployRecord->sourceUnit);
  }

  SetUpBattle(ourBattleStack, enemyBattleStack, compositionClass, fortLevel, battleSiteIndex);
}

// FUNCTION: IMPERIALISM 0x005a4da0
void TArmyBattle::WriteTo(TStream* stream) {
  stream->WriteBytes(&currentSide, 4);
  stream->WriteBytes(&battleLive, 4);

  TArmyPlayer* ourPlayer = static_cast<TArmyPlayer*>(players[0]);
  ourPlayer->AssertValid();
  int ourNationIndex = ourPlayer->armyStack->categoryFlag;
  stream->WriteBytes(&ourNationIndex, 4);
  int ourNationCode = ourPlayer->armyStack->ownerNationCode;
  stream->WriteBytes(&ourNationCode, 4);
  int ourTileIndex = ourPlayer->armyStack->tileIndex;
  stream->WriteBytes(&ourTileIndex, 4);

  TArmyPlayer* enemyPlayer = static_cast<TArmyPlayer*>(players[1]);
  enemyPlayer->AssertValid();
  int enemyNationIndex = enemyPlayer->armyStack->categoryFlag;
  stream->WriteBytes(&enemyNationIndex, 4);
  int enemyNationCode = enemyPlayer->armyStack->ownerNationCode;
  stream->WriteBytes(&enemyNationCode, 4);
  int enemyTileIndex = enemyPlayer->armyStack->tileIndex;
  stream->WriteBytes(&enemyTileIndex, 4);

  unsigned short unitRecordCount = recordList->GetCount();
  stream->WriteBytes(&unitRecordCount, sizeof(unitRecordCount));
  CIterator recordIter(recordList);
  for (TArmyTacUnit* record = static_cast<TArmyTacUnit*>(recordIter.Reset()); recordIter.More();
       record = static_cast<TArmyTacUnit*>(recordIter.Advance())) {
    int recordUnitId = record != 0 ? record->GetUID() : 0;
    stream->WriteBytes(&recordUnitId, 4);
    stream->WriteBytes(&record->side, 4);
    stream->WriteBytes(&record->field24, 2);
  }

  TArmyTacUnit* linked = static_cast<TArmyTacUnit*>(selectedUnit);
  int linkedUnitId = linked != 0 ? linked->GetUID() : 0;
  stream->WriteBytes(&linkedUnitId, 4);

  stream->WriteBytes(&battleSiteIndex, 4);
  stream->WriteBytes(&battleOutcome, 4);
  stream->WriteBytes(&fortLevel, 1);
  stream->WriteBytes(&currentTacticalActionCode, 4);
  stream->WriteBytes(&compositionClass, 4);
}

// FUNCTION: IMPERIALISM 0x005a4fc0
void TArmyBattle::LoadMap(int compositionClass, int fortLevel) {
  CString tabFileName;
  char nameBuf[64];
  int byteCount = tacticalTileCount + 0xf; // tiles + 15 row-terminator bytes
  sprintf(nameBuf, g_szBattleSetupTabPathFormat, compositionClass + 1);
  tabFileName = CString(nameBuf);

  char* tabData = new char[byteCount];
  CFile* stream = g_pAssetMgr->LoadTableResourceStreamByName(tabFileName);
  g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, tabData, &byteCount);
  g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);

  TacticalTileRecord* record = tileGrid;
  char* src = tabData;
  for (int row = 0; row < 15; ++row) {
    for (int col = 0; col < 29; ++col) {
      if (col < 0x1d - battlefieldColumnCount) {
        ++src; // margin char: no grid cell consumed
        continue;
      }
      if (fortLevel > 1 && col > 0x17) {
        record->terrainType = 0; // fort present (level >= 2): blank the last 5 columns
      } else {
        record->terrainType = *src; // movsx: signed char -> int
      }
      ++src;
      record->occupant = 0;
      record->deployMark = 0;
      record->mineRunState = -1;
      record->trenchMask = 0;
      ++record;
    }
    ++src;                                   // skip the row terminator byte
    record += 0x1d - battlefieldColumnCount; // skip the grid cells this row didn't cover
  }

  delete[] tabData;

  if (fortLevel != 0) {
    for (int tile = battlefieldColumnCount - 6; tile < 435; tile += 0x1d) {
      tileGrid[tile].deployMark = fortLevel;
    }
    for (int slot = 0; slot < 8; ++slot) {
      fortStrengthPoints[slot] = g_anFortStrengthPointsByFortLevel[fortLevel];
    }
  }
}

// FUNCTION: IMPERIALISM 0x005a51e0
void TArmyBattle::DeployUnit(TTacticalUnit* unit, TacticalTileIndex tileIndex) {
  unit->AssertValid();
  int column = tileIndex % 29;
  if (tileIndex < 29) {
    return;
  }
  TacticalTileRecord* record = &tileGrid[tileIndex];
  if (record->terrainType == 4) {
    return;
  }
  if (record->occupant != 0) {
    return;
  }
  if (currentSide == 0) {
    if (column < 3) {
      return;
    }
    if (column > 5) {
      return;
    }
  } else {
    if (column > battlefieldColumnCount - 3) {
      return;
    }
    if (column < battlefieldColumnCount - 5) {
      return;
    }
  }
  LaDeploy(static_cast<TArmyTacUnit*>(unit), tileIndex, false);
  TTacticalPlayer* sidePlayer = (currentSide == 0) ? players[0] : players[1];
  ApplyTacticalDoneSelectionAndRefreshUi(sidePlayer->GetNextUnit());
  for (int planeIndex = 0; planeIndex < tacticalTileCount; ++planeIndex) {
    tileMoveCostArray[planeIndex] = -1;
  }
  TTacticalPlayer* readyPlayer = (currentSide == 0) ? players[0] : players[1];
  if (readyPlayer->sideReadyFlag) {
    HandleRetreatCommand(); // side fully deployed -> hand the round over
    return;
  }
  if (battleView != 0) {
    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(battleView->ownerContext->FindSubView(kControlTagTool));
    toolbar->AssertValid();
    toolbar->ShowCurrentUnit(selectedUnit);
  }
}

// FUNCTION: IMPERIALISM 0x005a5320
void TArmyBattle::EndBattle(unsigned char sideWonFlag) {
  battleOutcome = kTacticalBattleSide0Victory;
  players[0]->AssertValid();
  players[1]->AssertValid();
  g_pSfxPlaybackSystem->StopMusic(false);

  if (battleView != 0) {
    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(battleView->ownerContext->FindSubView(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalOtherSideUnitControl(0);
    toolbar->ShowCurrentUnit(0);
  }

  g_pMapContextActionManager->EndTacticalBattle(static_cast<TArmyPlayer*>(players[0])->armyStack,
                                                static_cast<TArmyPlayer*>(players[1])->armyStack,
                                                sideWonFlag, battleSiteIndex);
}
