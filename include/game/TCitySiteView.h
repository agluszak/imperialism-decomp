#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006591d0
class TCitySiteView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TCitySiteView)
  virtual ~TCitySiteView();

  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;
  virtual void OrphanRetStub_005966a0(int arg1) override;
  virtual void OrphanRetStub_00596680(int arg1, int arg2) override;
  virtual undefined ReleaseRuntimeSelectionOwnerAndDestroyObject(int param_1, int param_2,
                                                                 int param_3) override;

  TCitySiteView();
};

// === BEGIN GENERATED (TCitySiteView) — refreshed by `just gen-class TCitySiteView`; do not hand-edit ===
// clang-format off
// vtable @ 0x006591d0 (165 slots), object size 0x378, base TMapDialog
//   slot 0x00  byte 0x00  0x0051be90  override  GetTEventHandlerClassNamePointer
//   slot 0x37  byte 0xdc  0x0051bff0  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x6d  byte 0x1b4  0x0051c3b0  override  OrphanRetStub_00596080
//   slot 0x75  byte 0x1d4  0x0051c760  override  HandleMapClickByInteractionMode
//   slot 0x78  byte 0x1e0  0x0051c2a0  override  OrphanRetStub_005966a0
//   slot 0x79  byte 0x1e4  0x0051c2f0  override  OrphanRetStub_00596680
//   slot 0xa3  byte 0x28c  0x0051c320  override  ReleaseRuntimeSelectionOwnerAndDestroyObject
// clang-format on
// === END GENERATED (TCitySiteView) ===
