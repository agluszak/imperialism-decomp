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
void TBook::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);
  field90 = ResolveControlByTag(kControlTagLcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xc, field90);
  field94 = ResolveControlByTag(kControlTagRcor);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xb, field94);
}

// FUNCTION: IMPERIALISM 0x0056f5e0
void TBook::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    // Tag family 'page'..'pagf': one control per page-list row.
    for (unsigned int tag = 0x70616765u; tag <= 0x70616766u; ++tag) {
      TView* pageControl = ResolveControlByTag(tag);
      if (pageControl != nullptr) {
        pageControl->QueryStepValue();
        // For the rcor/lcor tag branches, the original also reads pageControl's own
        // +0x62/+0x64 short fields and calls the currently-unowned 185-byte
        // UpdatePagedListNavigationButtonState (0x56f6c0) with a
        // (field62, field64 +/- field62) pair -- pageControl's concrete class (and those
        // two fields) is unresolved, so that adjustment is left unmodeled.
      }
    }
  }
  TPicture::HandleEvent(commandId, sourceHandler, event);
}
