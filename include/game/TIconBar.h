#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657a28
class TIconBar : public TNoHilitePicture {
public:
  virtual CRuntimeClass* GetRuntimeClass() const override;
  virtual ~TIconBar();

  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual void SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) override;
  virtual undefined OrphanCallChain_C2_I15_00506110(char param_1);
  virtual undefined OrphanTiny_SetWordEcxOffset_96_005060f0(undefined2 param_1);

  TIconBar();
};

// === BEGIN GENERATED (TIconBar) — refreshed by `just gen-class TIconBar`; do not hand-edit ===
// clang-format off
// vtable @ 0x00657a28 (118 slots), object size 0xb8, base TNoHilitePicture
//   slot 0x00  byte 0x00  0x00505fd0  override  GetTEventHandlerClassNamePointer
//   slot 0x44  byte 0x110  0x00506150  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x72  byte 0x1c8  0x005060c0  override  SetPictureResourceIdAndRefresh
//   slot 0x74  byte 0x1d0  0x00506110  override  OrphanCallChain_C2_I15_00506110
//   slot 0x75  byte 0x1d4  0x005060f0  override  OrphanTiny_SetWordEcxOffset_96_005060f0
// clang-format on
// === END GENERATED (TIconBar) ===
