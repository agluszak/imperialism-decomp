#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

class TDocument;

// VTABLE: IMPERIALISM 0x00644308
class TTEView : public TStaticText {
public:
  TTEView();
  void SetText(const CString& text); // 0x004861f0
  DECLARE_DYNCREATE(TTEView)
  virtual ~TTEView() override; // slot 0x01 (scalar deleting destructor)
  short GetNumberOfChars();
  void SetOneStyle(short start, short end, short styleMask, const TextStyle& style,
                   bool refreshNow);
  void StuffTERects(const CRect& textRect);
  int MeasureCurrentTextHeightInLayoutRect();
  void ITEView(TDocument* document, TView* panel, int* offsetLayout, int* sizeLayout,
               int layoutParam5, int layoutParam6, RECT* insetRect, TextStyle* style,
               short styleWord90, unsigned char unusedB, bool unusedC);

  bool field94;               // +0x94
  unsigned char field95;      // +0x95
  unsigned char padding96[2]; // +0x96
};
ASSERT_SIZE(TTEView, 0x98);
