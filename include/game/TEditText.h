#pragma once

#include "game/TStaticText.h"
#include "game/mfc.h"

class CityDialogController;

class CMcWindow;

// VTABLE: IMPERIALISM 0x0064ad90
class TEditText : public TStaticText {
public:
  CMcWindow* field_94; // 0x94
  int field_98;        // 0x98
  short field_9c;      // 0x9c
  short padding_9e;    // 0x9e

  DECLARE_DYNCREATE(TEditText)
  virtual ~TEditText();

  void Free() override;
  char GetBoolSlot28() override;
  void SetControlValue(int value) override;
  void HandleCityProductionNoOp() override;
  char ActivateCityProductionViewIfAllowed() override;
  void vmethod_0081(int) override;
  void DispatchSlot9CToLinkedChildren() override;
  void CallVoidSlotA0() override;
  void SetEnabled(int enabledState, int refreshFlag) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) override;
  void RecomputeAbsolutePositionRecursive() override;
  undefined SetTextThemeCodeAndMaybeRefresh(short themeCode, char refreshFlag) override;
  virtual undefined SetEditSelectionAndScrollCaret();
  virtual undefined WrapperFor_StringShared_AssignFromPtr_At00490c70(CString* param_1);
  virtual void InitDialogWindowAndSyncTitleIfChanged(CString* newText, int refreshFlag);

  TEditText();
};

// === BEGIN GENERATED (TEditText) — refreshed by `just gen-class TEditText`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064ad90 (121 slots), object size 0x94, base TStaticText
//   slot 0x00  byte 0x00  0x00490380  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x00492f30  override  VTableSlot01
//   slot 0x07  byte 0x1c  0x00490ad0  override  OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004906d0  override  GetTBehaviorClassNamePointer
//   slot 0x0b  byte 0x2c  0x004906f0  override  OrphanRetStub_0059ad90
//   slot 0x1b  byte 0x6c  0x00490c10  override  OrphanRetStub_0059add0
//   slot 0x1f  byte 0x7c  0x00490aa0  override  OrphanRetStub_0059add0
//   slot 0x21  byte 0x84  0x00490c30  override  OrphanRetStub_0059add0
//   slot 0x27  byte 0x9c  0x004907a0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x28  byte 0xa0  0x00490650  override  GetTEventHandlerClassNamePointer
//   slot 0x29  byte 0xa4  0x00490730  override  VTableSlot29
//   slot 0x44  byte 0x110  0x004906a0  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x46  byte 0x118  0x00490bc0  override  SetForeignMinisterReadyFlag14
//   slot 0x59  byte 0x164  0x00490e50  override  VTableSlot59
//   slot 0x71  byte 0x1c4  0x00490cb0  override  SetTextThemeCodeAndMaybeRefresh
//   slot 0x76  byte 0x1d8  0x00490a50  override  SetEditSelectionAndScrollCaret
//   slot 0x77  byte 0x1dc  0x00490c70  override  WrapperFor_StringShared_AssignFromPtr_At00490c70
//   slot 0x78  byte 0x1e0  0x00490cf0  override  InitDialogWindowAndSyncTitleIfChanged
// clang-format on
// === END GENERATED (TEditText) ===
