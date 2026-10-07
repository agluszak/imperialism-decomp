#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/TList.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00669598
class TTacticalPlayer : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalPlayer)
  // FUNCTION: IMPERIALISM 0x0059ae60
  virtual ~TTacticalPlayer() override {}
  virtual void Free() override;
  virtual void StartBattle();
  virtual void NextMove();
  virtual void DoClick(int unused);
  virtual void ApplyChanges(unsigned char sideWonFlag);
  virtual void RemoveCapturedUnit(class TTacticalUnit* unit);
  virtual void AddCapturedUnit(class TTacticalUnit* unit);
  virtual bool AlwaysTrueTacticalPredicate10(class TTacticalUnit* unit);
  virtual void ProceedAfterBattleIntroAccepted();

  TList* unitList;      // the side's tactical unit records (new TList())
  TList* secondaryList; // reserve list: never-deployed units
  char isOurSideFlag;
  char watchFlag;      // human-watch flag for this side
  bool notWatchedFlag; // = (watchFlag == 0)
  bool retreatOrdered;
  bool sideReadyFlag; // side ready (no undeployed unit remains)
  unsigned char pad11[3];
  class TTacticalBattle* battle; // back-pointer, set by battle setup
  int cursorIndex;               // round-robin cursor over unitList
  int nationIndex;               // owner nation index (+ 0xea6 = 'coat' bitmap id)
  bool skipRequested;
  unsigned char pad21[3];
  int field24;

  void ITacticalPlayer(unsigned char isOurSide, unsigned char watch, int nationIndex);

  class TTacticalUnit* GetNextUnit();

  void HandleSkipCommand();

  void RemoveReserves();

  // Whether this side belongs to the local active nation.
  bool IsPlayer();

  // NOOP: verified empty in original 0x0059ad42
  TTacticalPlayer() {}
};
ASSERT_SIZE(TTacticalPlayer, 0x28);
