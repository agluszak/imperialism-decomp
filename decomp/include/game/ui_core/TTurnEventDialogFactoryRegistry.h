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
  virtual ~TTurnEventDialogFactoryRegistry() override;

  virtual TView* ResolveDialogNodeByMessageContext(TurnEventId messageContext, int contextSlot);
  virtual TView* InvokeDialogFactoryFromPacket(int nContextId, TView* pEventPacket,
                                               TurnEventId nEventCode, const CPoint& anchorPoint);
  virtual TView* RunRegisteredDialogFactoriesByEventCode(int nContextId, TView* pEventPacket,
                                                         TurnEventId nEventCode,
                                                         const CPoint& anchorPoint);

  TTurnEventDialogFactoryRegistry();
  void RegisterDialogFactoryCallback(TurnEventDialogFactoryProc factory);

  CList<TurnEventDialogFactoryProc, TurnEventDialogFactoryProc> factories;
};

void RegisterStartupDialogFactoryCallbacks(TTurnEventDialogFactoryRegistry* registry);
