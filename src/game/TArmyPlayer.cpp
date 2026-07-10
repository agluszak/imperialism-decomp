#include "game/TArmyPlayer.h"

#include "game/TArmyStack.h"
#include "game/TArmyTacUnit.h"
#include "game/TList.h"
#include "game/TAssetMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalHolaPicture.h"
#include "game/global_data_tables.h"
#include "game/turn_event_dialog_provisional.h"
#include "game/ui_invalidation_guard.h"

extern undefined4 GenerateThreadLocalRandom15(void);

using turn_event_dialog::TurnEventDialogNode;
// SYNTHETIC: IMPERIALISM 0x0059b110
// TArmyPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059b140
// TArmyPlayer::`scalar deleting destructor'
TArmyPlayer::~TArmyPlayer() {}

// SYNTHETIC: IMPERIALISM 0x0059b190
// TArmyPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyPlayer, TTacticalPlayer)

// FUNCTION: IMPERIALISM 0x0059b1b0
void TArmyPlayer::InitializeTacticalSideFromArmyUnitList(TArmyStack* stack, int isOurSide,
                                                         char watchFlag, int nationIndex) {
  // Scatter-init of the side state, in the original store order.
  // TODO(verify): the asm only ever touches the low byte of `isOurSide` -- the
  // original param was likely char/BOOL.
  isOurSideFlagC = static_cast<char>(isOurSide);
  sideReadyFlag10 = 0;
  watchFlagD = watchFlag;
  nationIndex1C = nationIndex;
  cursorIndex18 = 0;
  fieldF = 0;
  field20 = 0;
  field24 = 0;

  unitList4 = new TList();
  sideReadyFlag10 = 0; // duplicate store present in the original
  secondaryList8 = new TList();

  // Walk the stack's embedded {TUnit*, next} chain. The original inlines the
  // TArmyStack::ResetCursorAndGetHeadUnit (0x4a3b70) / AdvanceCursorAndGetUnit
  // (0x4a3b90) bodies here (no calls emitted), so the walk is written out directly.
  stack->cursor18 = stack->head14;
  TUnit* unit;
  if (stack->head14 != 0) {
    unit = stack->head14->unit;
  } else {
    unit = 0;
  }
  while (unit != 0) {
    TArmyTacUnit* record = new TArmyTacUnit();
    record->ConstructTArmyTacUnitBaseState(static_cast<TMilitaryUnit*>(unit));
    unitList4->AddTail(record);
    if (static_cast<char>(isOurSide) == 0) {
      record->selectedFlag18 = 1; // TODO(verify): set only for the enemy side
    }
    TArmyStackUnitNode* node = stack->cursor18;
    if (node != 0) {
      node = node->next;
      stack->cursor18 = node;
      if (node != 0) {
        unit = node->unit;
      } else {
        unit = 0;
      }
    } else {
      unit = 0;
    }
  }

  armyStack28 = stack;
  cursorIndex18 = 0;      // duplicate store present in the original
  watchFlagD = watchFlag; // duplicate store present in the original
  notWatchedFlagE = (watchFlag == 0);
  field44 = -1;
  unsigned char coinFlip = static_cast<unsigned char>(GenerateThreadLocalRandom15() & 1);
  field4C = -1;
  randomParityByte50 = coinFlip;
  field51 = 0;
}

// FUNCTION: IMPERIALISM 0x0059b3e0
void TArmyPlayer::CommitTacticalResultsToSourceUnits(int unused) {
  // TODO: port body @ 0x59b3e0 (writes strength4 back to sourceUnit38 +0x34 and kills
  // zero-strength units via their slot 0x0c).
  (void)unused;
}

// FUNCTION: IMPERIALISM 0x0059b4f0
void TArmyPlayer::RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) {
  // TODO: port body @ 0x59b4f0.
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x0059b540
void TArmyPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  // TODO: port body @ 0x59b540.
  (void)unit;
}

// Kicks the side at battle start: unwatched (AI/remote) sides skip the intro dialog
// and auto-deploy; watched sides run the battle-intro ('hola', 0xf19) dialog and only
// proceed on 'okay'.
// FUNCTION: IMPERIALISM 0x0059b830
void TArmyPlayer::StartBattle() {
  if (notWatchedFlagE != 0) {
    SelectAndApplyTacticalCursorModeProfile(1);
    AutoDeploySideUnitsAndMarkReady();
    return;
  }
  unsigned char alreadyStarted = field24 == 2;
  if (alreadyStarted == 0) {
    TTacticalPlayer* opponent;
    if (isOurSideFlagC != 0) {
      opponent = battle14->tacticalPlayer18;
    } else {
      opponent = battle14->tacticalPlayer14;
    }
    int opposingNationIndex = opponent->nationIndex1C;

    // Battle-intro ("hola") dialog, id 0xf19.
    TurnEventDialogNode* dialog = static_cast<TurnEventDialogNode*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xf19));
    if (dialog == 0) {
      FailNilPointerWithAssert(s_SourcePathUTacPlayer_00699D84, 0x18d);
    }
    TTacticalHolaPicture* holaPicture =
        static_cast<TTacticalHolaPicture*>(dialog->ResolveControlByTag(0x444c4f47 /* 'DLOG' */));
    holaPicture->AssertValid();
    if (isOurSideFlagC != 0) {
      holaPicture->ConfigureBattleIntroCoatsAndSiteLabels(
          nationIndex1C, static_cast<short>(opposingNationIndex), isOurSideFlagC,
          battle14->battleSiteIndex38);
    } else {
      holaPicture->ConfigureBattleIntroCoatsAndSiteLabels(
          static_cast<short>(opposingNationIndex), nationIndex1C, 0, battle14->battleSiteIndex38);
    }
    int resultTag = dialog->RefreshTurnEventDialog();
    dialog->CallVoidSlotA0();
    dialog->Free();
    if (resultTag == 0x6f6b6179 /* 'okay' */) {
      ProceedAfterBattleIntroAccepted();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0059bc80
void TArmyPlayer::AutoDeploySideUnitsAndMarkReady() {
  // TODO: port body @ 0x59bc80 (auto-deploys the side and sets sideReadyFlag10).
}

// FUNCTION: IMPERIALISM 0x0059c3c0
undefined TArmyPlayer::TArmyTacUnit_VtblSlot07() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059c440
void TArmyPlayer::SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode) {
  // TODO: port body @ 0x59c440.
  (void)cursorProfileMode;
}

// FUNCTION: IMPERIALISM 0x0059e3e0
void TArmyPlayer::AdvanceTacticalTurnPulse() {
  // TODO: port body @ 0x59e3e0 (per-tick battle pump; runs the auto-turn controller
  // while notWatchedFlagE, with a GetAsyncKeyState(0x5c) cancel check).
}

// FUNCTION: IMPERIALISM 0x0059e4f0
undefined TArmyPlayer::RunTacticalAutoTurnControllerForActiveUnit() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059ea60
undefined TArmyPlayer::TArmyTacUnit_VtblSlot09() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059eb40
void TArmyPlayer::ProceedAfterBattleIntroAccepted() {
  // TODO: port body @ 0x59eb40 (auto-deploy when not ready, else flip notWatchedFlagE
  // for watched sides, cursor profile 0, dispatch slot 0x0b).
}
