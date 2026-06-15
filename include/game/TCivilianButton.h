#pragma once

#include "game/TRadioPictureButton.h"

extern "C" int g_vtblTCivilianButton;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTCivilianButton;

// VTABLE: IMPERIALISM 0x666da8
class TCivilianButton : public TRadioPictureButton {
public:
  short mappedSelection98;
  short selectedValue9c;

  TCivilianButton();
  virtual ~TCivilianButton() override;
  CRuntimeClass* GetRuntimeClass() const override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  void BeginMouseCaptureAndStartRepeatTimer(Point32* point, int arg2, int arg3, int arg4) override;
  void SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) override;
  bool IsSelected(short value = -1, bool refreshNow = true) override;

  void SetSelectionAndEnableByMappedValue(int selectedValue);
};
