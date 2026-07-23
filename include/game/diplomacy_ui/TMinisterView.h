#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TCountry;

// VTABLE: IMPERIALISM 0x00655100
class TMinisterView : public TView {
public:
  DECLARE_DYNCREATE(TMinisterView)
  virtual ~TMinisterView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f2e00
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,
                             CPoint origin) override; // slot 0x48 0x4f2d10
  // Stores the country descriptor for the selected nation slot. 0x4f2ce0.
  virtual void StuffValues(short nationSlot); // slot 0x68 0x4f2ce0
  // Resolves the 'disp' sub-picture (if present) and frees it. 0x4f2ef0.
  virtual void FreeDisplayArea(); // slot 0x69 0x4f2ef0
  // Closes floating books, then opens the turn-event help book identified by bookId.
  virtual TView* OpenBook(int bookId); // slot 0x6a 0x4f2ec0
  // Forwards to TDisplayMgr::CloseFloaters before minister navigation. 0x4f2ea0.
  virtual void CloseBooks(); // slot 0x6b 0x4f2ea0
  // TView's own fields end exactly at 0x60 (see TWorldView's identically-placed
  // viewportOffsetX); zeroed by the ctor, no other reader/writer found yet.
  int field60; // +0x60

  TMinisterView();

  // Original object size is 0x68 (CRuntimeClass m_nObjectSize); the source class ended
  // at 0x64. Written by StuffValues from g_apTerrainTypeDescriptorTable.
  TCountry* selectedCountry;
};
