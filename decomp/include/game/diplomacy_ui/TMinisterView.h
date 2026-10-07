#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_diplomacy.h"
#include "game/mfc.h"

class TCountry;

// VTABLE: IMPERIALISM 0x00655100
class TMinisterView : public TView {
public:
  DECLARE_DYNCREATE(TMinisterView)
  virtual ~TMinisterView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  // Stores the country descriptor for the selected nation slot.
  virtual void StuffValues(short nationSlot);
  // Resolves the 'disp' sub-picture (if present) and frees it.
  virtual void FreeDisplayArea();
  // Closes floating books, then opens the turn-event help book identified by bookId.
  virtual TView* OpenBook(int bookId);
  // Forwards to TDisplayMgr::CloseFloaters before minister navigation.
  virtual void CloseBooks();
  int field60;

  TMinisterView();

  TCountry* selectedCountry;
};
ASSERT_SIZE(TMinisterView, 0x68);
