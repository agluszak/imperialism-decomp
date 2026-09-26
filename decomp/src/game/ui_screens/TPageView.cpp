#include "game/ui_screens/TPageView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/CSubViewIterator.h"
#include "game/TList.h"
#include "game/city_ui/TLongintList.h"
#include "game/ui_screens/TLineData.h"

// SYNTHETIC: IMPERIALISM 0x0056f8e0
// TPageView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056f9a0
// TPageView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPageView, TView)

// FUNCTION: IMPERIALISM 0x0056f9c0
TPageView::TPageView() {
  this->orderedEntries = nullptr;
  this->pageStartIndices = nullptr;
  this->currentPage = -1;
  this->visibleColumnCount = 1;
}

// SYNTHETIC: IMPERIALISM 0x0056fa00
// TPageView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0056fa30
TPageView::~TPageView() {}

// FUNCTION: IMPERIALISM 0x0056fa50
void TPageView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  this->orderedEntries = new TList();
  this->optionEntries = new TList();
  this->pageStartIndices = new TLongintList();
  this->pageRect.bottom = this->frameHeight38 - 1;
  this->pageRect.top = 0;
  this->pageRect.left = 0;
  this->pageRect.right = this->frameWidth34 - 1;
}

// FUNCTION: IMPERIALISM 0x0056fbb0
POSITION TPageView::AddOrderedEntry(TLineData* item) {
  return this->orderedEntries->AddTail(item);
}

// FUNCTION: IMPERIALISM 0x0056fbd0
POSITION TPageView::AddOptionEntry(TLineData* item) {
  return this->optionEntries->AddTail(item);
}

// FUNCTION: IMPERIALISM 0x0056fbf0
void TPageView::ResetSelectableOptionEntriesExceptColorAndOkay() {
  // Skip "rocl"/"rocr" (color) and "yako" (okay) option-entry tags, plus "tond" resource IDs.
  static const unsigned int kColorTagA = kControlTagLcor; // "rocl"
  static const unsigned int kColorTagB = kControlTagRcor; // "rocr"
  static const unsigned int kOkayTag = kControlTagOkay;   // "yako"
  static const unsigned int kSkipId = kControlTagDont;    // "tond"

  // The original walks the option entries with the shared CSubViewIterator, not a raw
  // GetHeadPosition/GetNext loop.
  CSubViewIterator iter(this);
  TView* child = iter.FirstSubView();
  if (iter.MoreSubViews()) {
    do {
      if (child->controlTag != kColorTagA && child->controlTag != kColorTagB &&
          child->controlTag != kOkayTag && child->controlValue3c != kSkipId) {
        child->Free();
      }
      child = iter.NextSubView();
    } while (iter.MoreSubViews());
  }
}

// FUNCTION: IMPERIALISM 0x0056fc80
void TPageView::BuildPageLayout() {
  pageStartIndices->RemoveAll();

  // ABI: line bounds are ints, but retail pagination keeps signed-short coordinates
  // and reads only the low word of each line's height.
  short y = static_cast<short>(pageRect.top);
  short previousHeader = 0;
  short pages = 1;
  pageStartIndices->InsertLast(1);
  for (int ordinal = 1; ordinal <= orderedEntries->GetCount(); ++ordinal) {
    TLineData* entry = static_cast<TLineData*>(orderedEntries->GetEntryByOrdinal(ordinal));
    if (entry->row != 0 && entry->row != previousHeader) {
      previousHeader = entry->row;
      TLineData* header = static_cast<TLineData*>(optionEntries->GetEntryByOrdinal(entry->row));
      y += static_cast<short>(header->layoutHeight);
    }

    short height = static_cast<short>(entry->layoutHeight);
    if (y + entry->column + height > pageRect.bottom) {
      ++pages;
      y = static_cast<short>(pageRect.top + height);
      pageStartIndices->InsertLast(ordinal);
      if (entry->row != 0) {
        TLineData* header = static_cast<TLineData*>(optionEntries->GetEntryByOrdinal(entry->row));
        y += static_cast<short>(header->layoutHeight);
      }
    } else {
      y += height;
    }
  }

  pageCount = pages;
}

// FUNCTION: IMPERIALISM 0x0056fdb0
void TPageView::ShowPage(short pageNumber) {
  if (pageNumber < 1 || pageNumber > pageCount) {
    return;
  }

  ResetSelectableOptionEntriesExceptColorAndOkay();

  short previousHeader = 0;
  for (int column = pageNumber; column < pageNumber + visibleColumnCount; ++column) {
    if (pageStartIndices->GetSize() < column) {
      continue;
    }

    short y = static_cast<short>(pageRect.top);
    int perColumnWidth = frameWidth34 / visibleColumnCount;
    short x = static_cast<short>(pageRect.left + perColumnWidth * (column - pageNumber));
    short currentIndex = static_cast<short>(pageStartIndices->At(column));

    while (currentIndex <= orderedEntries->GetCount()) {
      TLineData* entry = static_cast<TLineData*>(orderedEntries->GetEntryByOrdinal(currentIndex));
      if (entry->row != 0 && entry->row != previousHeader) {
        previousHeader = entry->row;
        entry = static_cast<TLineData*>(optionEntries->GetEntryByOrdinal(entry->row));
        // The header precedes this row; installing it must not consume the row.
        --currentIndex;
      }

      if (y + entry->column + static_cast<short>(entry->layoutHeight) > pageRect.bottom) {
        break;
      }

      int offset[2] = {x, y};
      entry->InstallViews(this, offset);
      y += static_cast<short>(entry->layoutHeight);
      ++currentIndex;
    }
  }

  currentPage = pageNumber;
  RefreshControl();
}

// FUNCTION: IMPERIALISM 0x0056ff90
void TPageView::ResetPageLayout() {
  this->ResetSelectableOptionEntriesExceptColorAndOkay();
  this->optionEntries->RemoveAll();
  this->orderedEntries->RemoveAll();
  this->pageStartIndices->RemoveAll();
  this->currentPage = 0;
  this->pageCount = 0;
}

// FUNCTION: IMPERIALISM 0x0056ffe0
void TPageView::Free() {
  if (this->optionEntries != nullptr) {
    this->optionEntries->FreePayloadsAndDestroy();
  }
  if (this->orderedEntries != nullptr) {
    this->orderedEntries->FreePayloadsAndDestroy();
  }
  if (this->pageStartIndices != nullptr) {
    this->pageStartIndices->Free();
  }
  TView::Free();
}
