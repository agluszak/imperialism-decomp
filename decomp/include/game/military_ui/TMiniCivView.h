#pragma once

#include "game/core/CString.h"
#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x0064d9d0
class TMiniCivView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniCivView)
  virtual ~TMiniCivView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Hilite();

  // The civilian unit this row describes (stored by the second-phase init).
  TCivUnit* civUnit;
  // Assembled multi-line status text ("<order line>\n...").
  CString unitText;

  // NOOP: verified empty in original 0x004ab8f6
  TMiniCivView() {}

  void InitializeForCivilianUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                 TCivUnit* civUnit);
};

ASSERT_SIZE(TMiniCivView, 0x8c);
