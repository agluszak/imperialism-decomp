#include "game/TPageView.h"

#include "game/CSubViewIterator.h"
#include "game/TList.h"
#include "game/TLongintList.h"

// Option-entry item held in TPageView's optionEntries/orderedEntries lists. It carries the
// tag used to look up the actual renderable entry and the short metrics used by
// the page layout algorithms.
class TSelectableTextOptionEntry : public TObject {
public:
  virtual void PlaceAt(TPageView* owner, CPoint* position) = 0;

  short field_0x4;
  short tag;
  short field_0x8;
  short field_0xa;
  short field_0xc;
};

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
TPageView::~TPageView() {}

// FUNCTION: IMPERIALISM 0x0056fa50
void TPageView::DoPostCreate(int arg) {
  (void)arg;
  this->orderedEntries = new TList();
  this->optionEntries = new TList();
  this->pageStartIndices = new TLongintList();
  this->pageRect.bottom = this->frameHeight38 - 1;
  this->pageRect.top = 0;
  this->pageRect.left = 0;
  this->pageRect.right = this->frameWidth34 - 1;
}

// FUNCTION: IMPERIALISM 0x0056fbb0
POSITION TPageView::AddOrderedEntry(void* item) {
  return this->orderedEntries->AddTail(item);
}

// FUNCTION: IMPERIALISM 0x0056fbd0
POSITION TPageView::AddOptionEntry(void* item) {
  return this->optionEntries->AddTail(item);
}

// FUNCTION: IMPERIALISM 0x0056fbf0
void TPageView::ResetSelectableOptionEntriesExceptColorAndOkay() {
  // Skip "rocl"/"rocr" (color) and "yako" (okay) option-entry tags, plus "tond" resource IDs.
  static const unsigned int kColorTagA = 0x6c636f72; // "rocl"
  static const unsigned int kColorTagB = 0x72636f72; // "rocr"
  static const unsigned int kOkayTag = 0x6f6b6179;   // "yako"
  static const unsigned int kSkipId = 0x646f6e74;    // "tond"

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
  this->pageStartIndices->RemoveAll();
  this->pageStartIndices->InsertLast(1);

  int count = this->orderedEntries->GetCount();
  short y = (short)this->pageRect.top;
  short previousTag = 0;
  short overflowCount = 1;

  for (int i = 1; i <= count; i++) {
    TSelectableTextOptionEntry* entry =
        static_cast<TSelectableTextOptionEntry*>(this->orderedEntries->GetEntryByOrdinal(i));
    if (entry == nullptr) {
      continue;
    }
    short tag = entry->tag;
    if (tag != 0 && tag != previousTag) {
      previousTag = tag;
      TSelectableTextOptionEntry* lookup =
          static_cast<TSelectableTextOptionEntry*>(this->optionEntries->GetEntryByOrdinal(tag));
      if (lookup != nullptr) {
        y += lookup->field_0xc;
      }
    }

    short margin = entry->field_0x4;
    short height = entry->field_0xc;
    int bottom = (int)y + (int)margin + (int)height;
    if (bottom > this->pageRect.bottom) {
      overflowCount++;
      y = this->pageRect.top + height;
      this->pageStartIndices->InsertLast(i);
      if (entry->tag != 0) {
        TSelectableTextOptionEntry* lookup = static_cast<TSelectableTextOptionEntry*>(
            this->optionEntries->GetEntryByOrdinal(entry->tag));
        if (lookup != nullptr) {
          height = lookup->field_0xc;
        }
      }
    }

    y += height;
  }

  this->pageCount = overflowCount;
}

// FUNCTION: IMPERIALISM 0x0056fdb0
void TPageView::ShowPage(short pageNumber) {
  if (pageNumber < 1 || pageNumber > this->pageCount) {
    return;
  }

  this->ResetSelectableOptionEntriesExceptColorAndOkay();

  short previousTag = 0;
  for (int column = pageNumber; column < pageNumber + this->visibleColumnCount; column++) {
    if (this->pageStartIndices->GetSize() < column) {
      continue;
    }

    int startIndex = this->pageStartIndices->At(column);
    int perColumnWidth = this->frameWidth34 / this->visibleColumnCount;
    short x = (short)(this->pageRect.left + perColumnWidth * (column - pageNumber));

    int count = this->orderedEntries->GetCount();
    int currentIndex = startIndex;
    short y = (short)this->pageRect.top;

    while (currentIndex <= count) {
      TSelectableTextOptionEntry* entry = static_cast<TSelectableTextOptionEntry*>(
          this->orderedEntries->GetEntryByOrdinal(currentIndex));
      if (entry == nullptr) {
        break;
      }

      short tag = entry->tag;
      if (tag != 0 && tag != previousTag) {
        previousTag = tag;
        TSelectableTextOptionEntry* lookup =
            static_cast<TSelectableTextOptionEntry*>(this->optionEntries->GetEntryByOrdinal(tag));
        if (lookup != nullptr) {
          entry = lookup;
        }
      }

      short margin = entry->field_0x4;
      short height = entry->field_0xc;
      int bottom = (int)y + (int)margin + (int)height;
      if (bottom > this->pageRect.bottom) {
        break;
      }

      CPoint point(x, y);
      entry->PlaceAt(this, &point);

      y += height;
      currentIndex++;
    }
  }

  this->currentPage = pageNumber;
  this->RefreshControl();
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
