#pragma once

#include "compat.h"

#include "game/nation_domain_types.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644540
class TScenarioChooser : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TScenarioChooser)
  virtual ~TScenarioChooser() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;         // slot 0x07 0x57ab30
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;           // slot 0x0f 0x0057a050
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x57a310
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x579b80
  virtual void StartGame();                               // slot 0x74 0x57a350
  virtual void ExitScreen();                              // slot 0x75 0x57a2d0

  // ORACLE: Mac names TScenarioChooser::ShowInfo(int). The Windows body loads the
  // argument as a full dword, stores its low word as the selected scenario, and RET 4.
  // IMPERIALISM 0x0057a6e0.
  void ShowInfo(int scenarioIndex);

  TScenarioChooser();

  enum { kScenarioSlotCount = 64 };

  // Scenario slots appended to the list can be sparse when files are absent or the
  // multiplayer-only filter skips a slot, so selection maps through this compact row table.
  short scenarioIndexByListRow[kScenarioSlotCount]; // 0x94
  short scenarioListRowCount;                       // 0x114
  // +0x116..+0x117: natural alignment before the pointer table.
  char* nationDescriptionTextByNation[kMajorNationCount];   // 0x118
  short nationDescriptionLengthByNation[kMajorNationCount]; // 0x134
  // Selected scenario index (-1 = none); read by StartGame and ExitScreen. -1 also
  // short-circuits the whole
  // apply flow.
  short selectedScenarioIndex;                    // 0x142
  int difficultyLevelByNation[kMajorNationCount]; // 0x144
};
ASSERT_SIZE(TScenarioChooser, 0x160);
