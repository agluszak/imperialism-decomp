#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"
// Full TView definition required: MSVC500 instantiates DestructElements for the
// factory-pointer CList and demands the pointee type be complete.
#include "game/TView.h"

// Each factory receives the host window to bind into the built control tree (the tail
// PropagateUiResourceContextRecursive(pHostWindow) call in each builder); the registry
// sweep passes null and lets the tree bind its host window later.
typedef TView*(__cdecl* TurnEventDialogFactoryProc)(CWnd* pHostWindow, int nEventCode);

// Turn-event UI dialog factory registry (global @ 0x006a1b24). Owns the freelist-backed
// callback table used by TAssetMgr::ResolveTurnEventDialogNodeByMessageContext.
// VTABLE: IMPERIALISM 0x0064b2e8
class TTurnEventDialogFactoryRegistry : public TObject {
public:
  virtual ~TTurnEventDialogFactoryRegistry()
      override; // slot 0x01 0x491b10 (scalar deleting destructor)

  virtual TView* ResolveDialogNodeByMessageContext(int messageContext,
                                                   int contextSlot); // slot 0x0a 0x491c80
  virtual TView* InvokeDialogFactoryFromPacket(int nContextId, TView* pEventPacket, int nEventCode,
                                               int* pAnchorPoint); // slot 0x0b 0x491d80
  virtual TView* RunRegisteredDialogFactoriesByEventCode(int nContextId, TView* pEventPacket,
                                                         int nEventCode,
                                                         int* pAnchorPoint); // slot 0x0c 0x491cc0

  TTurnEventDialogFactoryRegistry();
  void RegisterDialogFactoryCallback(TurnEventDialogFactoryProc factory);

  // +0x04 — embedded MFC template list of registered factory callbacks (this TU's twin
  // copy of the CList vtable is 0x0064b328; ctor block size 10).
  CList<TurnEventDialogFactoryProc, TurnEventDialogFactoryProc> factories;
};

void EnsureTurnEventDialogFactoryRegistryInitialized();
void RegisterStartupDialogFactoryCallbacks(TTurnEventDialogFactoryRegistry* registry);
