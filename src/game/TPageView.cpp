#include "game/TPageView.h"

#include "game/CSubViewIterator.h"
#include "game/TList.h"
#include "game/TLongintList.h"

// Option-entry item held in TPageView's field_0x78/field_0x7c lists. It carries the
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
  this->field_0x7c = nullptr;
  this->field_0x80 = nullptr;
  this->field_0x62 = -1;
  this->field_0x64 = 1;
}

// SYNTHETIC: IMPERIALISM 0x0056fa00
// TPageView::`scalar deleting destructor'
TPageView::~TPageView() {}

// FUNCTION: IMPERIALISM 0x0056fa50
void TPageView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  this->field_0x7c = new TList();
  this->field_0x78 = new TList();
  this->field_0x80 = new TLongintList();
  this->pageRect.bottom = this->frameHeight38 - 1;
  this->pageRect.top = 0;
  this->pageRect.left = 0;
  this->pageRect.right = this->frameWidth34 - 1;
}

// FUNCTION: IMPERIALISM 0x0056fbb0
POSITION TPageView::OrphanCallChain_C1_I06_0056fbb0(void* item) {
  return this->field_0x7c->AddTail(item);
}

// FUNCTION: IMPERIALISM 0x0056fbd0
POSITION TPageView::OrphanCallChain_C1_I06_0056fbd0(void* item) {
  return this->field_0x78->AddTail(item);
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
undefined TPageView::OrphanCallChain_C8_I82_0056fc80() {
  this->field_0x80->RemoveAll();
  this->field_0x80->InsertLast(1);

  int count = this->field_0x7c->GetCount();
  short y = (short)this->pageRect.top;
  short previousTag = 0;
  short overflowCount = 1;

  for (int i = 1; i <= count; i++) {
    TSelectableTextOptionEntry* entry =
        static_cast<TSelectableTextOptionEntry*>(this->field_0x7c->GetEntryByOrdinal(i));
    if (entry == nullptr) {
      continue;
    }
    short tag = entry->tag;
    if (tag != 0 && tag != previousTag) {
      previousTag = tag;
      TSelectableTextOptionEntry* lookup =
          static_cast<TSelectableTextOptionEntry*>(this->field_0x78->GetEntryByOrdinal(tag));
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
      this->field_0x80->InsertLast(i);
      if (entry->tag != 0) {
        TSelectableTextOptionEntry* lookup = static_cast<TSelectableTextOptionEntry*>(
            this->field_0x78->GetEntryByOrdinal(entry->tag));
        if (lookup != nullptr) {
          height = lookup->field_0xc;
        }
      }
    }

    y += height;
  }

  this->field_0x60 = overflowCount;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0056fdb0
undefined TPageView::OrphanCallChain_C8_I118_0056fdb0(short param_1) {
  if (param_1 < 1 || param_1 > this->field_0x60) {
    return 0;
  }

  this->ResetSelectableOptionEntriesExceptColorAndOkay();

  short previousTag = 0;
  for (int column = param_1; column < param_1 + this->field_0x64; column++) {
    if (this->field_0x80->GetSize() < column) {
      continue;
    }

    int startIndex = this->field_0x80->At(column);
    int perColumnWidth = this->frameWidth34 / this->field_0x64;
    short x = (short)(this->pageRect.left + perColumnWidth * (column - param_1));

    int count = this->field_0x7c->GetCount();
    int currentIndex = startIndex;
    short y = (short)this->pageRect.top;

    while (currentIndex <= count) {
      TSelectableTextOptionEntry* entry = static_cast<TSelectableTextOptionEntry*>(
          this->field_0x7c->GetEntryByOrdinal(currentIndex));
      if (entry == nullptr) {
        break;
      }

      short tag = entry->tag;
      if (tag != 0 && tag != previousTag) {
        previousTag = tag;
        TSelectableTextOptionEntry* lookup =
            static_cast<TSelectableTextOptionEntry*>(this->field_0x78->GetEntryByOrdinal(tag));
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

  this->field_0x62 = param_1;
  this->RefreshControl();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0056ff90
void TPageView::OrphanCallChain_C4_I18_0056ff90() {
  this->ResetSelectableOptionEntriesExceptColorAndOkay();
  this->field_0x78->RemoveAll();
  this->field_0x7c->RemoveAll();
  this->field_0x80->RemoveAll();
  this->field_0x62 = 0;
  this->field_0x60 = 0;
}

// FUNCTION: IMPERIALISM 0x0056ffe0
void TPageView::Free() {
  if (this->field_0x78 != nullptr) {
    this->field_0x78->FreePayloadsAndDestroy();
  }
  if (this->field_0x7c != nullptr) {
    this->field_0x7c->FreePayloadsAndDestroy();
  }
  if (this->field_0x80 != nullptr) {
    this->field_0x80->Free();
  }
  TView::Free();
}
