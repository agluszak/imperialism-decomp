#include "game/TModalTemplateDialog.h"

TModalTemplateDialog::~TModalTemplateDialog() {
  DestroyListBoxAndHotKeyChildren();
}

// FUNCTION: IMPERIALISM 0x004152e0
void TModalTemplateDialog::DestroyListBoxAndHotKeyChildren() {
  if (modalCreated != 0) {
    CleanupModalCreateState();
  }
}
