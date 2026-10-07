#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TList;
class TLongintList;
class TLineData;

// VTABLE: IMPERIALISM 0x0065e270
class TPageView : public TView {
public:
  DECLARE_DYNCREATE(TPageView)
  virtual ~TPageView() override;
  virtual void Free() override;
  virtual void DoPostCreate(int arg) override;
  virtual POSITION AddOrderedEntry(TLineData* item);
  virtual POSITION AddOptionEntry(TLineData* item);
  virtual void ResetSelectableOptionEntriesExceptColorAndOkay();
  virtual void CalculatePageStarts();
  virtual void ShowPage(short pageNumber);
  virtual void Clear();

  short pageCount;
  short currentPage;        // ctor writes -1
  short visibleColumnCount; // ctor writes 1
  short reserved66;         // no accesses observed
  RECT pageRect;
  TList* optionEntries;  // owned TLineData section headers, indexed by row
  TList* orderedEntries; // owned TLineData rows in layout order
  TLongintList* pageStartIndices;

  TPageView();
};
ASSERT_SIZE(TPageView, 0x84);
