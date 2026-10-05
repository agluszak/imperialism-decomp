#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/ui_core/TApplication.h"

class TMapUberUberPicture;
class TStream;
class TWindow;

unsigned int GetTickCountDiv16();

// VTABLE: IMPERIALISM 0x0063e398
class TAmbitApplication : public TApplication {
public:
  TAmbitApplication() : TApplication() {
    edgeScrollTarget = 0;
    dispatchBusyFlag = false;
    languagePackId50 = 0;
  }

  DECLARE_DYNCREATE(TAmbitApplication)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05, 0x0049e2f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06, 0x0049e280
  virtual void Free() override;                    // slot 0x07, 0x0049e1a0

  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12, 0x0049e4b0

  virtual void HandleCursor(int x, int y, void* cursorRegion); // slot 0x2b, 0x0049e320
  // Mac-oracle name DoSetupMenus() — Windows no-op (tentative attribution).
  virtual void DoSetupMenus(); // slot 0x2c, 0x00414770
  // MacApp TAmbitApplication::CloseAndFreeWindow(TWindow*).
  virtual void CloseAndFreeWindow(TWindow* window); // slot 0x2d, 0x0049e4e0

  void IAmbitApplication(); // 0x49ded0

  TMapUberUberPicture* edgeScrollTarget;
  bool dispatchBusyFlag;
  unsigned char pad4d[3];
  int languagePackId50;
};
ASSERT_SIZE(TAmbitApplication, 0x54);
