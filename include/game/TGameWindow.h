#pragma once

#include "game/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656a98
class TGameWindow : public TWindow {
public:
  virtual CRuntimeClass* GetRuntimeClass() const override;
  virtual ~TGameWindow();

  virtual void Free() override;
  virtual void ForwardParam(int param) override;
  virtual void DispatchSlot9CToLinkedChildren() override;
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4) override;
  virtual char DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                         int arg4) override;
  virtual undefined UpdateTurnOrderNavigationWindowLayout() override;
  virtual undefined NoOpTurnOrderNavigationVtableSlotA() override;
  virtual undefined NoOpTurnOrderNavigationVtableSlotB() override;

  TGameWindow();
};

// === BEGIN GENERATED (TGameWindow) — refreshed by `just gen-class TGameWindow`; do not hand-edit ===
// clang-format off
// vtable @ 0x00656a98 (122 slots), object size 0x1e4, base TWindow
//   slot 0x00  byte 0x00  0x004ffbf0  override  GetTEventHandlerClassNamePointer
//   slot 0x07  byte 0x1c  0x00500240  override  DestroyTurnOrderNavigationWindowAndResetManagerSlot
//   slot 0x12  byte 0x48  0x004ffd70  override  HandleTurnOrderNavigationCommand
//   slot 0x27  byte 0x9c  0x004ffcb0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x46  byte 0x118  0x004ffd10  override  SetForeignMinisterReadyFlag14
//   slot 0x48  byte 0x120  0x004ffd40  override  InvalidateWindowRectFromHandleField1C
//   slot 0x77  byte 0x1dc  0x00500160  override  UpdateTurnOrderNavigationWindowLayout
//   slot 0x78  byte 0x1e0  0x00500200  override  NoOpTurnOrderNavigationVtableSlotA
//   slot 0x79  byte 0x1e4  0x00500220  override  NoOpTurnOrderNavigationVtableSlotB
// clang-format on
// === END GENERATED (TGameWindow) ===
