#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;

struct Rect32 {
  int left;
  int top;
  int right;
  int bottom;
};

// VTABLE: IMPERIALISM 0x6431B0
class TCivDescription : public TView {
public:
  DECLARE_DYNCREATE(TCivDescription)
  virtual ~TCivDescription();

  virtual void ApplyRectSlot110(RECT* rectBuffer) override; // slot 0x44 0x58f550
  virtual void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                    int arg4) override; // slot 0x47 0x58f1a0
  virtual void DispatchPictureResourceCommand(int eventType, void* eventSender, void* eventDataA,
                                              void* eventDataB); // slot 0x68 0x58fec0
  virtual void DeserializeCityProductionQueueCommand(int* boundsBuffer); // slot 0x69 0x58f7b0
  virtual void AssertCityProductionGlobalStateInitialized(int arg1,
                                                          int arg2); // slot 0x6a 0x5903c0
  short selectedCivilianClass;
  short ownerNationId;
  union {
    short targetTileCountsBySlot[5];
    struct {
      short pad_64[4];
      unsigned char legendInitialized;
      unsigned char pad_6d;
    };
  };
  Rect32 legendRects[16];
  unsigned char pad_170_to_16f[0]; // legends end at 0x170

  TCivDescription();

  void UpdateCivilianOrderClassAndRefreshTargetCounts(class TCivUnit* orderState);
  void UpdateCivilianOrderTargetTileCountsForOwnerNation(class TCivUnit* selectedOrder);
};

// === BEGIN GENERATED (TCivDescription) — refreshed by `just gen-class TCivDescription`; do not hand-edit ===
// clang-format off
// vtable @ 0x006431b0 (107 slots), object size 0x170, base TView
//   slot 0x00  byte 0x00  0x0058f0f0  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x0044a7a0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00485f70  inherited OrphanRetStub_0059ad90
//   slot 0x06  byte 0x18  0x00485f90  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x07  byte 0x1c  0x0048b0b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x08  byte 0x20  0x0048bfd0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x0048a280  inherited OrphanRetStub_0059add0
//   slot 0x10  byte 0x40  0x0048a2e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x0048a310  inherited VTableSlot11
//   slot 0x12  byte 0x48  0x0048a380  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x13  byte 0x4c  0x0048a480  inherited VTableSlot13
//   slot 0x14  byte 0x50  0x00415d50  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x15  byte 0x54  0x00415d70  inherited VTableSlot15
//   slot 0x16  byte 0x58  0x0048b180  inherited SetForeignMinisterReadyFlag14
//   slot 0x17  byte 0x5c  0x0048a530  inherited VTableSlot17
//   slot 0x18  byte 0x60  0x0048a550  inherited SetForeignMinisterReadyFlag14
//   slot 0x19  byte 0x64  0x0048a690  inherited VTableSlot19
//   slot 0x1a  byte 0x68  0x0048a6b0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1b  byte 0x6c  0x0048a650  inherited VTableSlot1B
//   slot 0x1c  byte 0x70  0x0048a6d0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1d  byte 0x74  0x0048a670  inherited VTableSlot1D
//   slot 0x1e  byte 0x78  0x0048a6f0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1f  byte 0x7c  0x0048a570  inherited VTableSlot1F
//   slot 0x20  byte 0x80  0x0048a5e0  inherited GetTEventHandlerClassNamePointer
//   slot 0x21  byte 0x84  0x0048a710  inherited VTableSlot21
//   slot 0x22  byte 0x88  0x0048a500  inherited GetTEventHandlerClassNamePointer
//   slot 0x23  byte 0x8c  0x0048a4a0  inherited VTableSlot23
//   slot 0x24  byte 0x90  0x0048a4d0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x25  byte 0x94  0x0048afd0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x26  byte 0x98  0x0048af80  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x27  byte 0x9c  0x0048c820  inherited GetTEventHandlerClassNamePointer
//   slot 0x28  byte 0xa0  0x0048c890  inherited GetTEventHandlerClassNamePointer
//   slot 0x29  byte 0xa4  0x0048b1c0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x2a  byte 0xa8  0x0048b070  inherited UpdateControlCachedIntFromWindowText
//   slot 0x2b  byte 0xac  0x00427200  inherited OrphanRetStub_0059add0
//   slot 0x2c  byte 0xb0  0x0048c250  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x2d  byte 0xb4  0x0048c1c0  inherited OrphanRetStub_0059add0
//   slot 0x2e  byte 0xb8  0x0048c1e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x2f  byte 0xbc  0x00430bd0  inherited VTableSlot2F
//   slot 0x30  byte 0xc0  0x0048b4b0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x31  byte 0xc4  0x0048ab90  inherited VTableSlot31
//   slot 0x32  byte 0xc8  0x0048b690  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x33  byte 0xcc  0x0048c000  inherited VTableSlot33
//   slot 0x34  byte 0xd0  0x0048c050  inherited SetForeignMinisterReadyFlag14
//   slot 0x35  byte 0xd4  0x0048c080  inherited SetForeignMinisterReadyFlag14
//   slot 0x36  byte 0xd8  0x0048aaf0  inherited SetForeignMinisterReadyFlag14
//   slot 0x37  byte 0xdc  0x0048ab70  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x38  byte 0xe0  0x0048abc0  inherited GetTEventHandlerClassNamePointer
//   slot 0x39  byte 0xe4  0x0048b6d0  inherited VTableSlot39
//   slot 0x3a  byte 0xe8  0x0048b1a0  inherited GetTEventHandlerClassNamePointer
//   slot 0x3b  byte 0xec  0x0048b200  inherited VTableSlot3B
//   slot 0x3c  byte 0xf0  0x0048b250  inherited GetTEventHandlerClassNamePointer
//   slot 0x3d  byte 0xf4  0x0048b3f0  inherited VTableSlot3D
//   slot 0x3e  byte 0xf8  0x0048b770  inherited GetTEventHandlerClassNamePointer
//   slot 0x3f  byte 0xfc  0x00427220  inherited VTableSlot3F
//   slot 0x40  byte 0x100  0x0048b7b0  inherited GetTEventHandlerClassNamePointer
//   slot 0x41  byte 0x104  0x0048b7e0  inherited VTableSlot41
//   slot 0x42  byte 0x108  0x0048b810  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x43  byte 0x10c  0x0048b8d0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x44  byte 0x110  0x0058f550  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x45  byte 0x114  0x0048b860  inherited GetTEventHandlerClassNamePointer
//   slot 0x46  byte 0x118  0x0048c450  inherited SetForeignMinisterReadyFlag14
//   slot 0x47  byte 0x11c  0x0058f1a0  override  VTableSlot47
//   slot 0x48  byte 0x120  0x0048c590  inherited UpdateControlCachedIntFromWindowText
//   slot 0x49  byte 0x124  0x00427240  inherited OrphanRetStub_0059add0
//   slot 0x4a  byte 0x128  0x00427260  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x4b  byte 0x12c  0x00427290  inherited OrphanRetStub_0059add0
//   slot 0x4c  byte 0x130  0x004272d0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x4d  byte 0x134  0x0048ba80  inherited VTableSlot4D
//   slot 0x4e  byte 0x138  0x0048ba40  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x4f  byte 0x13c  0x0048b700  inherited VTableSlot4F
//   slot 0x50  byte 0x140  0x0048bb00  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x51  byte 0x144  0x00427330  inherited VTableSlot51
//   slot 0x52  byte 0x148  0x0048bb60  inherited SetForeignMinisterReadyFlag14
//   slot 0x53  byte 0x14c  0x0048bbb0  inherited SetForeignMinisterReadyFlag14
//   slot 0x54  byte 0x150  0x0048bc30  inherited SetForeignMinisterReadyFlag14
//   slot 0x55  byte 0x154  0x0048bc60  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x56  byte 0x158  0x0048bb30  inherited GetTEventHandlerClassNamePointer
//   slot 0x57  byte 0x15c  0x00429410  inherited VTableSlot57
//   slot 0x58  byte 0x160  0x0048bce0  inherited GetTEventHandlerClassNamePointer
//   slot 0x59  byte 0x164  0x0048b2d0  inherited VTableSlot59
//   slot 0x5a  byte 0x168  0x0048c380  inherited GetTEventHandlerClassNamePointer
//   slot 0x5b  byte 0x16c  0x0048c6d0  inherited VTableSlot5B
//   slot 0x5c  byte 0x170  0x0048abe0  inherited GetTEventHandlerClassNamePointer
//   slot 0x5d  byte 0x174  0x0048ae60  inherited VTableSlot5D
//   slot 0x5e  byte 0x178  0x0048c970  inherited GetTEventHandlerClassNamePointer
//   slot 0x5f  byte 0x17c  0x0048c990  inherited VTableSlot5F
//   slot 0x60  byte 0x180  0x0048c9e0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x61  byte 0x184  0x0048ca00  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x62  byte 0x188  0x0048ca20  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x63  byte 0x18c  0x0048ca40  inherited GetTEventHandlerClassNamePointer
//   slot 0x64  byte 0x190  0x0048c750  inherited SetForeignMinisterReadyFlag14
//   slot 0x65  byte 0x194  0x0048c7a0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x66  byte 0x198  0x0048c7d0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x67  byte 0x19c  0x0048bac0  inherited OrphanRetStub_0059add0
//   slot 0x68  byte 0x1a0  0x0058fec0  override  RenderCivilianTargetLegendVariantB
//   slot 0x69  byte 0x1a4  0x0058f7b0  override  RenderCivilianTargetLegendVariantA
//   slot 0x6a  byte 0x1a8  0x005903c0  override  RenderCivilianTargetProfilePanel
// object size 0x170 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCivDescription) ===
