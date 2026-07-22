#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TView;
class TPtrList;
struct TToolboxEvent;
struct TQuickDrawSurfaceContext;

// Display-surface / GWorld manager (singleton g_pDisplayMgr @ 0x006a2158).
// VTABLE: IMPERIALISM 0x00656680
class TDisplayMgr : public TObject {
public:
  DECLARE_DYNCREATE(TDisplayMgr)
  virtual ~TDisplayMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4fea60
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void InitializeWindowAndMBarSize(); // slot 0x0a 0x4fe840
  virtual void MakeNewGWorld(TQuickDrawSurfaceContext*& outContext, short bitDepth,
                             const RECT& bounds);                           // slot 0x0b 0x4feab0
  virtual void ExamineGWorld();                                             // slot 0x0c 0x4feb80
  virtual void AboutToLoseControl(unsigned char saveState);                 // slot 0x0d 0x4febd0
  virtual void RegainControl(unsigned char restoreState);                   // slot 0x0e 0x4fed00
  virtual void SetMenuHeight(unsigned char menuHeight);                     // slot 0x0f 0x4fed50
  virtual void SetBitDepth(unsigned char bitDepth);                         // slot 0x10 0x4fed70
  virtual void CloseBooks();                                                // slot 0x11 0x4fec20
  virtual void DismissTouchyFloaters(TToolboxEvent* event);                 // slot 0x12 0x4fec50
  virtual void ModalMessage(CString message, const POINT& messagePosition); // slot 0x13 0x4fec80
  virtual void UpdateTheGWorld(short eventCode);                            // slot 0x14 0x4fedc0
  virtual void SetHiliteColor(const RGBQUAD* color);                        // slot 0x15 0x4fefc0
  virtual void CloseFloaters();                                             // slot 0x16 0x4ff000

  // Frees the TQuickDrawSurfaceContext record held in `slot` and clears the slot.
  // Real __thiscall on the display manager (every callsite loads ecx = g_pDisplayMgr)
  // even though the body never reads `this`. 0x4feb50, ret 4.
  void RemoveGWorld(TQuickDrawSurfaceContext*& surface);

  TView* activeDialog;      // +0x04
  short viewportMetric;     // +0x08 (default 8)
  short dialogActiveFlag;   // +0x0a
  short field0c;            // +0x0c
  short eventCode0e;        // +0x0e (0x7d1 / 0x7d2)
  RGBQUAD hiliteColor;      // +0x10
  RGBQUAD savedHiliteColor; // +0x14
  int field18;              // +0x18
  short clipSnapshotEvent;  // +0x1c
  unsigned short field1e;   // +0x1e
  // Turn-order-navigation-dialog scratch list, constructed in
  // InitializeWindowAndMBarSize as a real TPtrList -- not a TView
  // (bd d9p: the port previously typed this TView* and reinterpret_cast'd a bare
  // TSortedPtrList onto it, which made TDisplayMgr::Free's call resolve to TView's
  // 0x28-slot vtable entry instead of the list's; fixed to call the real list method).
  TPtrList* turnOrderList; // +0x20

  TDisplayMgr();
};

// g_pDisplayMgr and UDisplayMgr font globals — see game/global_data_tables.h.

struct GlobalViewportRectDefaultsRecord;

// 0x00497230 — lazily seeds default 640x480 viewport rect globals.
GlobalViewportRectDefaultsRecord** InitializeGlobalRectDefaultsIfUninitialized();

// 0x004931e0. Emits the default Win32 warning beep.
void PlayDefaultMessageBeep();
