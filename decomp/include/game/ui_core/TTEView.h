#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

class TDocument;

// VTABLE: IMPERIALISM 0x00644308
class TTEView : public TStaticText {
public:
  TTEView();
  void SetText(const CString& text);
  DECLARE_DYNCREATE(TTEView)
  virtual ~TTEView() override;
  short GetNumberOfChars();
  void SetOneStyle(short start, short end, short styleMask, const TextStyle& style,
                   bool refreshNow);
  void StuffTERects(const CRect& textRect);
  int MeasureCurrentTextHeightInLayoutRect();
  void ITEView(TDocument* document, TView* panel, int* offsetLayout, int* sizeLayout,
               int layoutParam5, int layoutParam6, RECT* insetRect, TextStyle* style,
               short styleWord90, unsigned char unusedB, bool unusedC);

  bool editingEnabled;
  unsigned char field95;
  unsigned char padding96[2];
};
ASSERT_SIZE(TTEView, 0x98);
