#pragma once

#include "game/TPicture.h"

class TDeluxeText;
struct HelpSetRecord;
#include "game/mfc.h"
#include "game/ui_tags_screens.h"

// VTABLE: IMPERIALISM 0x00657080
class THelpPicture : public TPicture {
public:
  DECLARE_DYNCREATE(THelpPicture)
  virtual ~THelpPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00503ed0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x503d10
  virtual void ShowNextHelpSet();               // slot 0x73 0x504120
  virtual void ShowPreviousHelpSet();           // slot 0x74 0x5041a0
  virtual void ShowTopicList();                 // slot 0x75 0x5046c0
  virtual void ShowTopic(short topic);          // slot 0x76 0x504220

  THelpPicture();

  // The list-navigation methods read HelpSetRecord word fields through +0x90. DoPostCreate
  // allocates a TDeluxeText, stores it at +0x94, and attaches it to the 'swin' control.
  HelpSetRecord* currentHelpSet90;
  TDeluxeText* topicListText94;
};
