#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x667d08
class TStratReportView : public TView {
  DECLARE_DYNCREATE(TStratReportView)
public:
  char pad_60_to_63[0x04];

  TStratReportView();
  virtual ~TStratReportView() override;

  // slot 0x110 0x58e460 -- renders the battle-outcome header winner/loser
  // score lines; body not yet fully ported (CString/QuickDraw table render).
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
};
