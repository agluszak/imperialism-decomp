#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e958
class TTradeTotalsView : public TView {
public:
  DECLARE_DYNCREATE(TTradeTotalsView)
  virtual ~TTradeTotalsView() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5c1bd0

  TTradeTotalsView();

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended
  // at 0x60. The low short of the trailing 4 bytes is this row's nation slot (0..6),
  // read throughout Draw to index g_apNationStates[]; the high short is
  // still unobserved.
  short nationSlot;
  short unknown62;
};
ASSERT_SIZE(TTradeTotalsView, 0x64);
