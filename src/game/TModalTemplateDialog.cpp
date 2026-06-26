#include "game/TModalTemplateDialog.h"

#include "game/TMovieView.h"

namespace {

HWND ResolvePreModalOwner() {
  if (AfxGetApp() == nullptr || AfxGetApp()->m_pMainWnd == nullptr) {
    return nullptr;
  }
  return AfxGetApp()->m_pMainWnd->GetSafeHwnd();
}

} // namespace

TModalTemplateDialog::TModalTemplateDialog()
    : TControl(), resourceTemplateId(0), templateInitContext(nullptr), lockedTemplateBytes(nullptr),
      templateSourceCopy(0), hDialogResource(nullptr), hModalDialog(nullptr), ownerWasDisabled(0),
      hOwnerWindow(nullptr), modalCreated(0), promptText() {}

TModalTemplateDialog::~TModalTemplateDialog() {
  DestroyListBoxAndHotKeyChildren();
}

// FUNCTION: IMPERIALISM 0x006050d0
TControl* TModalTemplateDialog::InitializeDialogTemplateFromId(UINT templateId, void* initParam) {
  memset(&field3c, 0, 0x20);
  templateInitContext = initParam;
  field3c = static_cast<int>(templateId);
  resourceTemplateId = templateId & 0xffff;
  modalCreated = 0;
  hModalDialog = nullptr;
  ownerWasDisabled = 0;
  hOwnerWindow = nullptr;
  hDialogResource = nullptr;
  lockedTemplateBytes = nullptr;
  return this;
}

// FUNCTION: IMPERIALISM 0x0049d360
int TModalTemplateDialog::PrepareAndCreateModalFromTemplate() {
  lockedTemplateBytes = field48;
  templateSourceCopy = reinterpret_cast<int>(childList44);
  hDialogResource = reinterpret_cast<HGLOBAL>(templateSourceCopy);
  if (resourceTemplateId != 0) {
    AFX_MODULE_STATE* moduleState = AfxGetModuleState();
    HMODULE module = moduleState->m_hCurrentInstanceHandle;
    HRSRC resourceInfo =
        FindResourceA(module, MAKEINTRESOURCEA(resourceTemplateId), RT_DIALOG);
    hDialogResource = LoadResource(module, resourceInfo);
  }
  if (hDialogResource != nullptr) {
    lockedTemplateBytes = LockResource(hDialogResource);
  }
  if (lockedTemplateBytes == nullptr) {
    return 0;
  }

  hOwnerWindow = ResolvePreModalOwner();
  ownerWasDisabled = 0;
  if (hOwnerWindow != nullptr && IsWindowEnabled(hOwnerWindow)) {
    EnableWindow(hOwnerWindow, FALSE);
    ownerWasDisabled = 1;
  }
  hModalDialog = ::CreateDialogIndirectA(AfxGetInstanceHandle(),
                                       static_cast<LPCDLGTEMPLATE>(lockedTemplateBytes),
                                       hOwnerWindow, nullptr);
  field5c = 1;
  modalCreated = 1;
  return hModalDialog != nullptr ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x0049d450
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
  if (ownerWasDisabled != 0) {
    EnableWindow(hOwnerWindow, TRUE);
  }
  if (hOwnerWindow != nullptr) {
    HWND activeWindow = GetActiveWindow();
    CWnd* dialogWnd = CWnd::FromHandlePermanent(hModalDialog);
    if (dialogWnd != nullptr && activeWindow == dialogWnd->m_hWnd) {
      SetActiveWindow(hOwnerWindow);
    }
  }
  const int result = field2c;
  commandTagResourceByte = 1;
  padding_65_to_67[0] = 0;
  padding_65_to_67[1] = 0;
  padding_65_to_67[2] = 0;
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
