#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"

class TView;

typedef TView*(__cdecl* TurnEventDialogFactoryProc)(int nContextSlot, int nEventCode);

// Turn-event UI dialog factory registry (global @ 0x006a1b24). Owns the freelist-backed
// callback table used by TAssetMgr::ResolveTurnEventDialogNodeByMessageContext.
// VTABLE: IMPERIALISM 0x0064b2e8
class TTurnEventDialogFactoryRegistry : public TObject {
public:
  // slot 0x00 GetRuntimeClass inherited unchanged (0x485e20)
  virtual ~TTurnEventDialogFactoryRegistry(); // slot 0x01 0x491b10 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)

  virtual TView* ResolveDialogNodeByMessageContext(int messageContext,
                                                   int contextSlot); // slot 0x0a 0x491c80
  virtual TView* InvokeDialogFactoryFromPacket(int nContextId, TView* pEventPacket, int nEventCode,
                                               int* pAnchorPoint); // slot 0x0b 0x491d80
  virtual TView* RunRegisteredDialogFactoriesByEventCode(int nContextId, TView* pEventPacket,
                                                         int nEventCode,
                                                         int* pAnchorPoint); // slot 0x0c 0x491cc0

  TTurnEventDialogFactoryRegistry();
  void RegisterDialogFactoryCallback(TurnEventDialogFactoryProc factory);

  struct CallbackNode {
    CallbackNode* next;
    CallbackNode* previousTail;
    TurnEventDialogFactoryProc factory;
  };

  char* runtimeClassSentinel; // +0x04
  CallbackNode* listHead;     // +0x08
  CallbackNode* listTail;     // +0x0c
  int registeredCount;        // +0x10
  CallbackNode* freeList;     // +0x14
  int blockPoolHead;          // +0x18
  int blockPoolCapacity;      // +0x1c
};

void EnsureTurnEventDialogFactoryRegistryInitialized();

// Document/bootstrap object (0x54 bytes) that owns the registry during CAmbitDocument setup.
int* CreateTurnEventDialogFactoryRegistryObject();
int* InitializeTurnEventDialogFactoryRegistry(void* storage, int* bootstrap);
void DestroyTurnEventDialogFactoryRegistryAndReleaseGlobalFactory(int* bootstrap);
