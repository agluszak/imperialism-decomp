#include "game/TModalTemplateDialog.h"

#include <new.h>

#include "game/TMovieView.h"

TModalTemplateDialog::TModalTemplateDialog()
    : TControl(), resourceTemplateId(0), templateInitContext(nullptr), lockedTemplateBytes(nullptr),
      templateSourceCopy(0), hDialogResource(nullptr), hModalDialog(nullptr), ownerWasDisabled(0),
      hOwnerWindow(nullptr), modalCreated(0), promptText() {}

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
  if (hModalDialog == nullptr) {
    return FALSE;
  }
  CDialog dialog;
  dialog.Attach(hModalDialog);
  const BOOL result = dialog.UpdateData(saveAndValidate);
  dialog.Detach();
  return result;
}

TControl* TModalTemplateDialog::InitializeDialogTemplateFromId(UINT templateId, void* initParam) {
  TModalTemplateDialogBase::InitializeDialogTemplateFromId(templateId, initParam);
  templateInitContext = initParam;
  resourceTemplateId = templateId & 0xffff;
  modalCreated = 0;
  hModalDialog = nullptr;
  ownerWasDisabled = 0;
  hOwnerWindow = nullptr;
  hDialogResource = nullptr;
  lockedTemplateBytes = nullptr;
  return this;
}

int TModalTemplateDialog::PrepareAndCreateModalFromTemplate() {
  const int result = TModalTemplateDialogBase::PrepareAndCreateModalFromTemplate();
  lockedTemplateBytes = field48;
  templateSourceCopy = reinterpret_cast<int>(childList44);
  hDialogResource = reinterpret_cast<HGLOBAL>(field70);
  hOwnerWindow = reinterpret_cast<HWND>(field6C);
  ownerWasDisabled = field68;
  hModalDialog = reinterpret_cast<HWND>(hasCommandTagResource);
  modalCreated = field5c;
  return result;
}

int TModalTemplateDialog::FinalizeModalDialogAndRestoreOwnerFocus() {
  if (modalCreated == 0) {
    CallVoidSlotA0();
  }
  if (hasCommandTagResource != 0) {
    if ((ownerOffsetX & 0x10) != 0) {
      unsigned char loopKind = 4;
      CWnd* dialogWnd = CWnd::FromHandlePermanent(hModalDialog);
      if (dialogWnd != nullptr && (dialogWnd->GetStyle() & 0x100) != 0) {
        loopKind = 5;
      }
      TMovieView::RunModalLoop(reinterpret_cast<TMovieView*>(this), loopKind);
    }
    CWnd* dialogWnd = CWnd::FromHandlePermanent(hModalDialog);
    if (dialogWnd != nullptr) {
      dialogWnd->SetWindowPos(nullptr, 0, 0, 0, 0,
                              SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE |
                                  SWP_HIDEWINDOW | SWP_NOSENDCHANGING);
    }
  }
  const int result = TModalTemplateDialogBase::FinalizeModalDialogAndRestoreOwnerFocus();
  hModalDialog = nullptr;
  ownerWasDisabled = 0;
  modalCreated = 0;
  return result;
}

// FUNCTION: IMPERIALISM 0x0049d510
void TModalTemplateDialog::CleanupModalCreateState() {
  if (modalCreated != 0) {
    CallVoidSlotA0();
    if (AfxGetApp() != nullptr) {
      AfxGetApp()->EnableModeless(TRUE);
    }
    hModalDialog = nullptr;
    ownerWasDisabled = 0;
    modalCreated = 0;
    field5c = 0;
  }
}
