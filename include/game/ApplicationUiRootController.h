#pragma once

#include "decomp_types.h"
#include "game/ApplicationUiRootEmbeddedList.h"
#include "game/TEventHandler.h"

class TView;

// Application UI root controller — global modal-view gatekeeper installed at startup.
// Inherits the shared 37-slot base interface (indices 0x00-0x24) and fields through +0x1c
// from TEventHandler (the same base TView derives from). Introduces its own slot 0x25,
// then active-view get/set at vtable indices 0x26/0x27 (byte offsets 0x98/0x9c). An
// embedded CObList-like sub-object lives at +0x2c (secondary vtable 0x00648ca8). Size 0x48.
// VTABLE: IMPERIALISM 0x00648bd8
class ApplicationUiRootController : public TEventHandler {
public:
  ApplicationUiRootController();
  ~ApplicationUiRootController() override;

  // vtable index 0x00 override (0x00486740): returns the TApplication CRuntimeClass.
  virtual CRuntimeClass* GetRuntimeClass() override;

  // vtable index 0x25: AppRoot-introduced slot (unported placeholder; TEventHandler's
  // base vtable is null here, so this is a new virtual, not an inherited one).
  virtual void vmethod_0037();
  // vtable index 0x26 (0x00486880): store the active modal view pointer.
  virtual void SetActiveView(TView* view);
  // vtable index 0x27 (0x004868a0): load the active modal view pointer.
  virtual TView* GetActiveView();

  virtual void vmethod_0038();
  virtual void vmethod_0039();
  virtual void vmethod_003a();

  TView* activeView;                          // 0x20
  int screenModeAt24;                         // 0x24
  int field28;                                // 0x28
  ApplicationUiRootEmbeddedList embeddedList; // 0x2c
};

extern ApplicationUiRootController* g_pApplicationUiRootController;
