#pragma once

#include "compat.h"
#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/ui_core/TView.h"
#include "game/turn_event_codes.h"

typedef TView*(__cdecl* TurnEventDialogFactoryProc)(CWnd* pHostWindow, int nEventCode);

// VTABLE: IMPERIALISM 0x0064b2e8
class TTurnEventDialogFactoryRegistry : public TObject {
public:
  virtual ~TTurnEventDialogFactoryRegistry()
      override; // slot 0x01 0x491b10 (scalar deleting destructor)

  virtual TView* ResolveDialogNodeByMessageContext(TurnEventId messageContext,
                                                   int contextSlot); // slot 0x0a 0x491c80
  virtual TView* InvokeDialogFactoryFromPacket(int nContextId, TView* pEventPacket,
                                               TurnEventId nEventCode,
                                               const CPoint& anchorPoint); // slot 0x0b 0x491d80
  virtual TView*
  RunRegisteredDialogFactoriesByEventCode(int nContextId, TView* pEventPacket,
                                          TurnEventId nEventCode,
                                          const CPoint& anchorPoint); // slot 0x0c 0x491cc0

  TTurnEventDialogFactoryRegistry();
  void RegisterDialogFactoryCallback(TurnEventDialogFactoryProc factory);

  CList<TurnEventDialogFactoryProc, TurnEventDialogFactoryProc> factories;
};

void RegisterStartupDialogFactoryCallbacks(TTurnEventDialogFactoryRegistry* registry);
