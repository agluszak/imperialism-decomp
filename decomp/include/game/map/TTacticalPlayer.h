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
  virtual ~TTacticalPlayer() override {}                // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                         // slot 0x07 0x59aee0
  virtual void StartBattle();                           // slot 0x0a 0x59ad70
  virtual void NextMove();                              // slot 0x0b 0x59ad90
  virtual void DoClick(int unused);                     // slot 0x0c 0x59adb0
  virtual void ApplyChanges(unsigned char sideWonFlag); // slot 0x0d 0x59add0
  virtual void RemoveCapturedUnit(class TTacticalUnit* unit);            // slot 0x0e 0x59afa0
  virtual void AddCapturedUnit(class TTacticalUnit* unit);               // slot 0x0f 0x59afe0
  virtual bool AlwaysTrueTacticalPredicate10(class TTacticalUnit* unit); // slot 0x10 0x59adf0
  virtual void ProceedAfterBattleIntroAccepted();                        // slot 0x11 0x59ae10

  TList* unitList;               // +0x04 the side's tactical unit records (new TList())
  TList* secondaryList;          // +0x08 reserve list: never-deployed units (0x59b740)
  char isOurSideFlag;            // +0x0c
  char watchFlag;                // +0x0d human-watch flag for this side
  bool notWatchedFlag;           // +0x0e = (watchFlag == 0)
  bool retreatOrdered;           // +0x0f
  bool sideReadyFlag;            // +0x10 side ready (no undeployed unit remains)
  unsigned char pad11[3];        // +0x11
  class TTacticalBattle* battle; // +0x14 back-pointer, set by battle setup (0x59f890)
  int cursorIndex;               // +0x18 round-robin cursor over unitList
  int nationIndex;               // +0x1c owner nation index (+ 0xea6 = 'coat' bitmap id)
  bool skipRequested;            // +0x20
  unsigned char pad21[3];        // +0x21
  int field24;                   // +0x24

  void ITacticalPlayer(unsigned char isOurSide, unsigned char watch, int nationIndex);

  class TTacticalUnit* GetNextUnit();

  void HandleTacticalCommandTag_skip();

  void RemoveReserves();

  // Whether this side belongs to the local active nation. 0x0059b010, __thiscall.
  bool IsPlayer();

  // NOOP: verified empty in original 0x0059ad42
  TTacticalPlayer() {}
};
ASSERT_SIZE(TTacticalPlayer, 0x28);
