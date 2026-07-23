#include "game/ui_screens/TBook.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/ui_screens/TPageView.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00430250
TBook::TBook() {
  previousPageButton = 0;
  nextPageButton = 0;
}

// SYNTHETIC: IMPERIALISM 0x00430280
// TBook::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004302b0
TBook::~TBook() {}
// SYNTHETIC: IMPERIALISM 0x0056f4a0
// TBook::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056f540
// TBook::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBook, TPicture)

// FUNCTION: IMPERIALISM 0x0056f560
void TBook::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);
  previousPageButton = ResolveControlByTag(kControlTagLcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xc, previousPageButton);
  nextPageButton = ResolveControlByTag(kControlTagRcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xb, nextPageButton);
}

// FUNCTION: IMPERIALISM 0x0056f5e0
void TBook::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    // Tag family 'page'..'pagf': one control per page-list row. Each tag's control is
    // handled independently -- the row-count refresh below runs once per tag (up to
    // twice), seeded from THAT tag's own control, not a single re-resolved 'page'
    // control after the loop.
    for (int tag = kControlTagPage; tag <= kControlTagPagf; ++tag) {
      TPageView* pageControl = static_cast<TPageView*>(ResolveControlByTag(tag));
      if (pageControl != nullptr) {
        pageControl->AssertValid();
        short currentPage = pageControl->currentPage;
        short visibleCount = pageControl->visibleColumnCount;
        if (sourceHandler->controlTag == kControlTagRcor) {
          pageControl->ShowPage(static_cast<short>(visibleCount + currentPage));
          ShowPage(currentPage);
        } else if (sourceHandler->controlTag == kControlTagLcor) {
          pageControl->ShowPage(static_cast<short>(currentPage - visibleCount));
          ShowPage(currentPage);
        }
      }
    }
  }
  TPicture::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0056f6c0
void TBook::ShowPage(int currentPage) {
  TPageView* pageControl = static_cast<TPageView*>(ResolveControlByTag(kControlTagPage));
  pageControl->AssertValid();

  if (currentPage == 1) {
    previousPageButton->SetState(0, 0);
    previousPageButton->SetEnabled(0, 1);
  } else {
    previousPageButton->SetState(1, 0);
    previousPageButton->SetEnabled(1, 1);
  }

  if (pageControl->visibleColumnCount + currentPage <= pageControl->pageCount) {
    nextPageButton->SetState(0, 0);
    nextPageButton->SetEnabled(0, 1);
  } else {
    nextPageButton->SetState(1, 0);
    nextPageButton->SetEnabled(1, 1);
  }
}
