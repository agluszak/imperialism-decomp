#include "game/TBook.h"

#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00430280
// TBook::`scalar deleting destructor'
TBook::~TBook() {}
// SYNTHETIC: IMPERIALISM 0x0056f4a0
// TBook::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056f540
// TBook::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBook, TPicture)

// FUNCTION: IMPERIALISM 0x00430250
TBook::TBook() {}

// FUNCTION: IMPERIALISM 0x0056f560
void TBook::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);
  previousPageButton = ResolveControlByTag(kControlTagLcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xc, previousPageButton);
  nextPageButton = ResolveControlByTag(kControlTagRcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xb, nextPageButton);
}

// FUNCTION: IMPERIALISM 0x0056f5e0
void TBook::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    // Tag family 'page'..'pagf': one control per page-list row. Each tag's control is
    // handled independently -- the row-count refresh below runs once per tag (up to
    // twice), seeded from THAT tag's own control, not a single re-resolved 'page'
    // control after the loop.
    for (unsigned int tag = 0x70616765u; tag <= 0x70616766u; ++tag) {
      TControl* pageControl = static_cast<TControl*>(ResolveControlByTag(tag));
      if (pageControl != nullptr) {
        pageControl->AssertValid();
        // frameStyle60 is packed (its high word is the page-list row count, matching
        // TControl's own documented "packs two values" comment). The visible-count read
        // is 16 bits wide starting at controlState64 -- wider than controlState64 alone,
        // so it also picks up the adjacent padding byte (both already-declared fields,
        // no new cast needed).
        short rowCount = static_cast<short>(pageControl->frameStyle60 >> 16);
        short visibleCount = static_cast<short>(pageControl->controlState64 |
                                                (pageControl->padding_65_to_67[0] << 8));
        if (sourceHandler->controlTag == kControlTagRcor) {
          pageControl->ReturnZeroFromUiSlot6C(visibleCount + rowCount);
          UpdatePagedListNavigationButtonState(rowCount);
        } else if (sourceHandler->controlTag == kControlTagLcor) {
          pageControl->ReturnZeroFromUiSlot6C(rowCount - visibleCount);
          UpdatePagedListNavigationButtonState(rowCount);
        }
      }
    }
  }
  TPicture::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0056f6c0
void TBook::UpdatePagedListNavigationButtonState(int rowCount) {
  TControl* pageControl = static_cast<TControl*>(ResolveControlByTag(0x70616765u /* 'page' */));
  pageControl->AssertValid();

  if (rowCount == 1) {
    previousPageButton->SetState(0, 0);
    previousPageButton->SetEnabled(0, 1);
  } else {
    previousPageButton->SetState(1, 0);
    previousPageButton->SetEnabled(1, 1);
  }

  short lowWord = static_cast<short>(pageControl->frameStyle60);
  short visibleCount =
      static_cast<short>(pageControl->controlState64 | (pageControl->padding_65_to_67[0] << 8));
  if (visibleCount + rowCount <= lowWord) {
    nextPageButton->SetState(0, 0);
    nextPageButton->SetEnabled(0, 1);
  } else {
    nextPageButton->SetState(1, 0);
    nextPageButton->SetEnabled(1, 1);
  }
}
