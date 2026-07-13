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

BOOL TModalTemplateDialog::UpdateData(BOOL saveAndValidate) {
  if (createdDialog == nullptr) {
    return FALSE;
  }
  CDialog dialog;
  dialog.Attach(createdDialog);
  const BOOL result = dialog.UpdateData(saveAndValidate);
  dialog.Detach();
  return result;
}

// FUNCTION: IMPERIALISM 0x0049d510
void TModalTemplateDialog::CleanupModalCreateState() {
  if (modalCreated != 0) {
    DestroyWindow();
    PostModal();
    finalizeState = 0;
    createdDialog = nullptr;
    modalCreated = 0;
  }
}
