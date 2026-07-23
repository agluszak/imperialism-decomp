#include "game/TBattleDetailBook.h"
#include "game/TWindow.h"

#include "game/TControl.h"
#include "game/ui_tags_common.h"

// SYNTHETIC: IMPERIALISM 0x00430b00
// TBattleDetailBook::`scalar deleting destructor'
TBattleDetailBook::~TBattleDetailBook() {}
// SYNTHETIC: IMPERIALISM 0x004ae9d0
// TBattleDetailBook::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aea70
// TBattleDetailBook::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBattleDetailBook, TBook)

TBattleDetailBook::TBattleDetailBook() {}

// FUNCTION: IMPERIALISM 0x004aea90
void TBattleDetailBook::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagOkay) {
    GetWindow()->Dismiss(sourceHandler->controlTag, 1);
    return;
  }
  TBook::DoEvent(commandId, sourceHandler, event);
}
