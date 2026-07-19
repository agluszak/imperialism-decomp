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
void TBook::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}
