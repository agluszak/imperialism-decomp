#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/ui_tags_screens.h"

class TDeluxeText;
struct HelpSetRecord;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657080
class THelpPicture : public TPicture {
public:
  DECLARE_DYNCREATE(THelpPicture)
  virtual ~THelpPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void ShowNextHelpSet();
  virtual void ShowPreviousHelpSet();
  virtual void ShowTopicList();
  virtual void ShowTopic(short topic);

  THelpPicture();

  HelpSetRecord* currentHelpSet;
  TDeluxeText* topicListText;
};
ASSERT_SIZE(THelpPicture, 0x98);
