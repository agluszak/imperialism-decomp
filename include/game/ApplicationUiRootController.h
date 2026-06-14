#pragma once

#include "decomp_types.h"
#include "game/ApplicationUiRootEmbeddedList.h"
#include "game/UiDialogHandlerPrefix.h"

class TView;

// Application UI root controller — global modal-view gatekeeper installed at startup.
// Shares the city-dialog vtable prefix (indices 0x00-0x25) with TView/TControl; introduces
// active-view get/set at vtable indices 0x26/0x27 (byte offsets 0x98/0x9c). An embedded
// CObList-like sub-object lives at +0x2c (secondary vtable 0x00648ca8). Size 0x48.
// VTABLE: IMPERIALISM 0x00648bd8
class ApplicationUiRootController : public UiDialogHandlerPrefix {
public:
  ApplicationUiRootController();
  ~ApplicationUiRootController();

  // vtable index 0x26 (0x00486880): store the active modal view pointer.
  virtual void SetActiveView(TView* view);
  // vtable index 0x27 (0x004868a0): load the active modal view pointer.
  virtual TView* GetActiveView();

  virtual void vmethod_0038();
  virtual void vmethod_0039();
  virtual void vmethod_003a();

  TView* activeView;           // 0x20
  int screenModeAt24;          // 0x24
  int field28;                 // 0x28
  ApplicationUiRootEmbeddedList embeddedList; // 0x2c
};

extern ApplicationUiRootController* g_pApplicationUiRootController;
