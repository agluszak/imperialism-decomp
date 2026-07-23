#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643c78
class TSpecialQuitPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TSpecialQuitPicture)
  virtual ~TSpecialQuitPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005b4a10
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5b4810
  virtual void Hilite();                        // slot 0x73 0x45acb0

  // NOOP: verified empty in original 0x00458dcb (trivial inline ctor: the builder
  // expansion site emits only the base ctor call + vtbl install)
  TSpecialQuitPicture() {}

  // Original object size is 0x94 (CRuntimeClass m_nObjectSize); the source class ended at
  // 0x90. DoEvent reads/writes quitAnimationFrame90 exclusively via 16-bit `ax`/`word ptr` accesses
  // (both the `= 1` init and the increment/compare/decrement loop), so it's a short, not
  // an int; padA2 keeps sizeof at 0x94.
  short quitAnimationFrame90;
  short padA2;
};
