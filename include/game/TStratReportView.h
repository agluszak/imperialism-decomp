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
};
