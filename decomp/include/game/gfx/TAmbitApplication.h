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
    languagePackId = 0;
  }

  DECLARE_DYNCREATE(TAmbitApplication)
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;

  virtual void DoKeyEvent(TToolboxEvent* event) override;

  virtual void HandleCursor(int x, int y, void* cursorRegion);
  virtual void DoSetupMenus();
  // MacApp TAmbitApplication::CloseAndFreeWindow(TWindow*).
  virtual void CloseAndFreeWindow(TWindow* window);

  void IAmbitApplication();

  TMapUberUberPicture* edgeScrollTarget;
  bool dispatchBusyFlag;
  unsigned char pad4d[3];
  int languagePackId;
};
ASSERT_SIZE(TAmbitApplication, 0x54);
