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
  virtual ~TScenarioChooser() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void StartGame();
  virtual void ExitScreen();

  void ShowInfo(int scenarioIndex);

  TScenarioChooser();

  enum { kScenarioSlotCount = 64 };

  short scenarioIndexByListRow[kScenarioSlotCount];
  short scenarioListRowCount;
  // +0x116..+0x117: natural alignment before the pointer table.
  char* nationDescriptionTextByNation[kMajorNationCount];
  short nationDescriptionLengthByNation[kMajorNationCount];
  short selectedScenarioIndex;
  int difficultyLevelByNation[kMajorNationCount];
};
ASSERT_SIZE(TScenarioChooser, 0x160);
