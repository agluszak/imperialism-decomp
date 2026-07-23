#pragma once

#include "game/ui_screens/CString.h"
#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TCivUnit;

// Per-civilian-unit info line view (the "mini civ" row): shows the unit's current
// order/state as assembled text (unitText88).
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

  // Trivial in-class ctor (heuristic 116): the factory's `new TMiniCivView()`
  // (TMiniCivLine::InstallViews 0x4ab740) inline-expands the TControl base
  // ctor call, the unitText88 CString ctor, and the vptr store.
  TMiniCivView() {}

  // MacApp second-phase init (0x4ab970): frames the control, binds the civ unit,
  // and assembles unitText88 from the unit's UnitOrder state.
  void InitializeForCivilianUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                 TCivUnit* civUnit);
};

ASSERT_SIZE(TMiniCivView, 0x8c);
