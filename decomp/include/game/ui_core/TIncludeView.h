#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00649c60
class TIncludeView : public TView {
public:
  DECLARE_DYNCREATE(TIncludeView)
  virtual ~TIncludeView() override;
  virtual void DoPostCreate(int arg) override;
  short turnEventCode;
  short padding62;
  CPoint anchorPoint;
  CString labelText;
  short completionFlag;
  short padding72;

  // Turn-event factory packet builder (thiscall on the freshly-constructed entry).
  void IIncludeView(TView* resourceContext, TView* mainView, short eventCode,
                    const CPoint& anchorPoint, CString* labelText, int flag);

  TIncludeView();
};

ASSERT_SIZE(TIncludeView, 0x74);
