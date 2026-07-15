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
