#pragma once

#include "compat.h"

#include "game/navy/TMilitaryPageView.h"
#include "game/ui_tags_common.h"

class TTaskForce;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065cbd0
class TNavyRoster : public TMilitaryPageView {
public:
  DECLARE_DYNCREATE(TNavyRoster)
  virtual ~TNavyRoster() override;
  virtual void Close() override;
  virtual void StuffValues(TTaskForce* taskForce);

  TNavyRoster();

  TTaskForce* taskForce;
  int unresolvedZero; // constructor-only zero dword
  TView* classControls[4];
  unsigned char paddingA0[0xd0 - 0xa0];
};
ASSERT_SIZE(TNavyRoster, 0xd0);
