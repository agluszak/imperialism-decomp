#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00649c60
class TIncludeView : public TView {
public:
  DECLARE_DYNCREATE(TIncludeView)
  virtual ~TIncludeView() override;            // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x48cfd0
  short turnEventCode60;
  short padding62;
  int anchorPoint64[2];
  CString labelText6c;
  short completionFlag70;
  short padding72;

  // Turn-event factory packet builder (thiscall on the freshly-constructed entry).
  void BuildTurnEventFactoryPacket(TView* resourceContext, TView* mainView, short eventCode,
                                   int* anchorPoint, CString* labelText, int flag);

  TIncludeView();
};

ASSERT_SIZE(TIncludeView, 0x74);
