#pragma once

#include "game/TView.h"

// Engineer-dialog view (university advanced status UI). Mac: TEngineerDialog::Free, Draw.
// VTABLE: IMPERIALISM 0x652d60
class TEngineerDialog : public TView {
public:
  int field60; // 0x60 — header blit surface handle
  int field64; // 0x64 — footer blit surface handle
  int field68; // 0x68 — body tile blit surface handle

  TEngineerDialog();
  virtual ~TEngineerDialog() override;

  virtual CRuntimeClass* GetRuntimeClass() const override; // 0x00 0x4d0540
  void Free() override;                                    // 0x1c 0x4d05e0
  void ApplyRectSlot110(RECT* rectBuffer) override;        // 0x110 0x4d0650
};
