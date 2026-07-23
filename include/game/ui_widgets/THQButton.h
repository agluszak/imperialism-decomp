#pragma once

#include "game/ui_core/TPicture.h"

extern "C" int g_vtblTHQButton;
struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x666fe0
class THQButton : public TPicture {
public:
  DECLARE_DYNCREATE(THQButton)
  virtual ~THQButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0058b7f0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x58b6e0
  virtual void HiliteState(unsigned char enabledState,
                           unsigned char refreshNow) override;          // slot 0x70 0x58b750
  virtual bool IsSelected(short value = -1, bool refreshNow = true);    // slot 0x73 0x58b890
  virtual void SetSelectionStateAndRefreshBitmap(short selectionState); // slot 0x74 0x58b8d0
  short glyph90;
  short timingWord92;
  short glyph94;
  short glyph96;
  short glyph98;
  char pad_9a[2];

  THQButton();
};
