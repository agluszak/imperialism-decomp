#pragma once

#include "game/TObject.h"
#include "game/TList.h"
#include "game/mfc.h"

// TODO(manifest): describe TTacticalPlayer and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalPlayer -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669598
class TTacticalPlayer : public TObject {
public:
  // === BEGIN GENERATED DECLS (TTacticalPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTacticalPlayer)
  virtual ~TTacticalPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x59aee0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void StartBattle();                                             // slot 0x0a 0x59ad70
  virtual void AdvanceTacticalTurnPulse();                                // slot 0x0b 0x59ad90
  virtual void NoOpTacticalPlayerHook0C(int unused);                      // slot 0x0c 0x59adb0
  virtual void CommitTacticalResultsToSourceUnits(int unused);            // slot 0x0d 0x59add0
  virtual void RemoveTacticalUnitFromUnitList(class TTacticalUnit* unit); // slot 0x0e 0x59afa0
  virtual void AddTacticalUnitToUnitListHead(class TTacticalUnit* unit);  // slot 0x0f 0x59afe0
  virtual unsigned char AlwaysTrueTacticalPredicate10(int unused);        // slot 0x10 0x59adf0
  virtual void ProceedAfterBattleIntroAccepted();                         // slot 0x11 0x59ae10
  // === END GENERATED DECLS (TTacticalPlayer) ===

  // Base slice (+0x04..+0x27; TArmyPlayer appends at +0x28 up to 0x54). Evidence:
  // battle setup 0x59f890 (unitList4/battle14 on both players), army side init 0x59b1b0
  // (scatter-init of the whole slice), selection 0x59af20, coat control 0x5a9b40.
  TList* unitList4;                // +0x04 the side's tactical unit records (new TList())
  TList* secondaryList8;           // +0x08 second owned list; use TODO(verify)
  char isOurSideFlagC;             // +0x0c
  char watchFlagD;                 // +0x0d human-watch flag for this side
  char notWatchedFlagE;            // +0x0e = (watchFlagD == 0)
  char fieldF;                     // +0x0f
  char sideReadyFlag10;            // +0x10 side ready (no undeployed unit remains)
  unsigned char pad11[3];          // +0x11
  class TTacticalBattle* battle14; // +0x14 back-pointer, set by battle setup (0x59f890)
  int cursorIndex18;               // +0x18 round-robin cursor over unitList4
  int nationIndex1C;               // +0x1c owner nation index (+ 0xea6 = 'coat' bitmap id)
  char field20;                    // +0x20
  unsigned char pad21[3];          // +0x21
  int field24;                     // +0x24

  // Returns the next selectable unit (tileIndex8 != -2) from unitList4, advancing
  // cursorIndex18. Body TODO. 0x0059af20, __thiscall.
  class TTacticalUnit* SelectNextTacticalUnitForDoneCommand();

  // Whether this side belongs to the local active nation. 0x0059b010, __thiscall.
  unsigned char IsTacticalControllerOwnedByActiveNation();

  // Derived construction sites inline the whole ctor chain as a bare vptr store, so
  // this must stay empty and in-class.
  TTacticalPlayer() {}
};
