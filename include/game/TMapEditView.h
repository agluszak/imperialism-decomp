#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006594e8
class TMapEditView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TMapEditView)
  virtual ~TMapEditView();

  virtual void ForwardParam(int param) override;
  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext) override;
  virtual void HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2) override;
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord,
                                                     int dispatchContext) override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;

  TMapEditView();
};

// === BEGIN GENERATED (TMapEditView) — refreshed by `just gen-class TMapEditView`; do not hand-edit ===
// clang-format off
// vtable @ 0x006594e8 (165 slots), object size 0x370, base TMapDialog
//   slot 0x00  byte 0x00  0x0051cc40  override  GetTEventHandlerClassNamePointer
//   slot 0x12  byte 0x48  0x0051deb0  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x37  byte 0xdc  0x0051cc60  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x71  byte 0x1c4  0x0051cfa0  override  InvokeDialogHooks1D8ThenE4
//   slot 0x72  byte 0x1c8  0x0051d210  override  HandleMapTileClickSetOrderContextAndDispatchEvent79
//   slot 0x73  byte 0x1cc  0x0051d060  override  ApplyCityInfluenceTierAndInvalidateTileCaches
//   slot 0x75  byte 0x1d4  0x0051ce60  override  HandleMapClickByInteractionMode
// clang-format on
// === END GENERATED (TMapEditView) ===
