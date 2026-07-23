#pragma once

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644308
class TTEView : public TStaticText {
public:
  TTEView();
  using TStaticText::SetText;
  // Mac oracle: TTEView::SetText(const CStr255&). CString is the Windows counterpart.
  void SetText(const CString& text); // 0x004861f0
  DECLARE_DYNCREATE(TTEView)
  virtual ~TTEView() override; // slot 0x01 (scalar deleting destructor)
  short GetNumberOfChars();
  void SetOneStyle(short start, short end, short styleMask, const TextStyle& style,
                   unsigned char refreshNow);
  void StuffTERects(const CRect& textRect);
  // Measures the wrapped text height produced by DrawText(DT_CALCRECT) inside the
  // inset content rectangle. The original returns bounds.bottom - bounds.top.
  int MeasureCurrentTextHeightInLayoutRect();
  // Mac-style second-phase init (not the ctor — no vtable store): runs the TStaticText
  // base init, copies the 0x68-0x74 inset rect and the packed text-style descriptor,
  // and seeds textAlignmentCode. Args 1, 10 and 11 are never read (TDeluxeText passes
  // 0, 0, 1).
  // 0x486050, __thiscall, RET 0x2c.
  void InitializeTextEntryView(int unusedA, TView* panel, int* offsetLayout, int* sizeLayout,
                               int layoutParam5, int layoutParam6, RECT* insetRect,
                               TextStyle* style, short styleWord90, int unusedB, int unusedC);

  // Original object size is 0x98 (CRuntimeClass m_nObjectSize). These three
  // members previously sat at the head of TDeluxeText, but the RTTI sizes prove
  // they belong here: sizeof(TTEView)=0x98 and TDeluxeText's remaining fields
  // then land exactly on their offset-suffixed names (cursorThemeCode98 @0x98).
  unsigned char field94;      // +0x94
  unsigned char field95;      // +0x95
  unsigned char padding96[2]; // +0x96
};
