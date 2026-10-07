#include "game/ui_screens/TBook.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/ui_screens/TPageView.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00430250
TBook::TBook() : TPicture() {
  previousPageButton = 0;
  nextPageButton = 0;
}

// FUNCTION: IMPERIALISM 0x004302b0
TBook::~TBook() {}

IMPLEMENT_DYNCREATE(TBook, TPicture)

// FUNCTION: IMPERIALISM 0x0056f560
void TBook::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);
  previousPageButton = FindSubView(kControlTagLcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xc, previousPageButton);
  nextPageButton = FindSubView(kControlTagRcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xb, nextPageButton);
}

// FUNCTION: IMPERIALISM 0x0056f5e0
void TBook::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 10) {
    TPicture::DoEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId == 10) {
    for (int tag = kControlTagPage; tag <= kControlTagPagf; ++tag) {
      TPageView* pageControl = static_cast<TPageView*>(FindSubView(tag));
      if (pageControl != NULL) {
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
  TPageView* pageControl = static_cast<TPageView*>(FindSubView(kControlTagPage));
  pageControl->AssertValid();

  if (currentPage == 1) {
    previousPageButton->ViewEnable(0, 0);
    previousPageButton->Show(0, 1);
  } else {
    previousPageButton->ViewEnable(1, 0);
    previousPageButton->Show(1, 1);
  }

  if (pageControl->visibleColumnCount + currentPage <= pageControl->pageCount) {
    nextPageButton->ViewEnable(0, 0);
    nextPageButton->Show(0, 1);
  } else {
    nextPageButton->ViewEnable(1, 0);
    nextPageButton->Show(1, 1);
  }
}
