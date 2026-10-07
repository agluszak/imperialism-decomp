#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f650
class TBook : public TPicture {
public:
  DECLARE_DYNCREATE(TBook)
  virtual ~TBook() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TBook();

  TView* previousPageButton; // resolved by tag 'lcor'
  TView* nextPageButton;     // resolved by tag 'rcor'

  void ShowPage(int currentPage);
};
ASSERT_SIZE(TBook, 0x98);
