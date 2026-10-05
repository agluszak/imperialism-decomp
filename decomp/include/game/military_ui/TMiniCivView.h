#pragma once

#include "game/core/CString.h"
#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x0064d9d0
class TMiniCivView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniCivView)
  virtual ~TMiniCivView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004ac320
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4ac000
  virtual void Hilite();                        // slot 0x71 0x4ab800

  // The civilian unit this row describes (stored by the second-phase init).
  TCivUnit* civUnit84;
  // Assembled multi-line status text ("<order line>\n...").
  CString unitText88;

  TMiniCivView() {}

  void InitializeForCivilianUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                 TCivUnit* civUnit);
};

ASSERT_SIZE(TMiniCivView, 0x8c);
