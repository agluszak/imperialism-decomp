#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f650
class TBook : public TPicture {
public:
  DECLARE_DYNCREATE(TBook)
  virtual ~TBook() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0056f5e0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x56f560

  TBook();

  TView* previousPageButton; // 0x90, resolved by tag 'lcor'
  TView* nextPageButton;     // 0x94, resolved by tag 'rcor'

  // Mac name oracle: TBook::ShowPage(long). The Windows method updates the pager
  // buttons from the current page and the 'page' TPageView's layout fields.
  void ShowPage(int currentPage); // 0x56f6c0
};
