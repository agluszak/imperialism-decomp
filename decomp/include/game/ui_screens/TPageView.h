#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TList;
class TLongintList;

// VTABLE: IMPERIALISM 0x0065e270
class TPageView : public TView {
public:
  DECLARE_DYNCREATE(TPageView)
  virtual ~TPageView() override;                // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x56ffe0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x56fa50
  virtual POSITION AddOrderedEntry(void* item); // slot 0x68 0x56fbb0
  virtual POSITION AddOptionEntry(void* item);  // slot 0x69 0x56fbd0
  virtual void ResetSelectableOptionEntriesExceptColorAndOkay(); // slot 0x6a 0x56fbf0
  virtual void BuildPageLayout();                                // slot 0x6b 0x56fc80
  virtual void ShowPage(short pageNumber);                       // slot 0x6c 0x56fdb0
  virtual void ResetPageLayout();                                // slot 0x6d 0x56ff90

  short pageCount;                // +0x60
  short currentPage;              // +0x62, ctor writes -1
  short visibleColumnCount;       // +0x64, ctor writes 1
  short reserved66;               // +0x66, no accesses observed
  RECT pageRect;                  // +0x68
  TList* optionEntries;           // +0x78, entries referenced by their tag/index
  TList* orderedEntries;          // +0x7c, rows in layout order
  TLongintList* pageStartIndices; // +0x80

  TPageView();
};
ASSERT_SIZE(TPageView, 0x84);
