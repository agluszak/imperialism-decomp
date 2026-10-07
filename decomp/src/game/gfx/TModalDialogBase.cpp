
#include "game/gfx/TModalDialogBase.h"

#include "game/mfc.h"
#include "game/pointer_representation.h"
#include <afxpriv.h>

// FUNCTION: IMPERIALISM 0x00413b80
TModalDialogBase::~TModalDialogBase() {
  if (finalizeState != 0) {
    CleanupModalCreateState();
  }
}

// FUNCTION: IMPERIALISM 0x00480750
TModalDialogBase::TModalDialogBase(UINT nIDTemplate, CWnd* pParentWnd)
    : CDialog(nIDTemplate, pParentWnd), modalCreated(0), dialogCreatedSuccessfully(0),
      finalizeState(0) {}

// FUNCTION: IMPERIALISM 0x0049d360
int TModalDialogBase::PrepareAndCreateModalFromTemplate() {
  void* templateBytes = const_cast<void*>(static_cast<const void*>(m_lpDialogTemplate));
  loadedResource = m_hDialogTemplate;
  const UINT templateId = reinterpret_cast<UINT>(m_lpszTemplateName);
  if (templateId != 0) {
    AFX_MODULE_STATE* moduleState = AfxGetModuleState();
    HMODULE module = moduleState->m_hCurrentInstanceHandle;
    HRSRC resourceInfo = ::FindResourceA(module, MAKEINTRESOURCEA(templateId), RT_DIALOG);
    if (resourceInfo == nullptr) {
      return 0;
    }
    loadedResource = ::LoadResource(module, resourceInfo);
  }
  if (loadedResource != nullptr) {
    templateBytes = ::LockResource(loadedResource);
  }
  if (templateBytes == nullptr) {
    return 0;
  }

  ownerWindow = PreModal();
  AfxUnhookWindowCreate();
  CWnd* owner = CWnd::FromHandle(ownerWindow);
  ownerWasDisabled = 0;
  if (ownerWindow != nullptr && ::IsWindowEnabled(ownerWindow)) {
    ::EnableWindow(ownerWindow, FALSE);
    ownerWasDisabled = 1;
  }
  AfxHookWindowCreate(this);
  dialogCreatedSuccessfully = CreateDlgIndirect(static_cast<LPCDLGTEMPLATE>(templateBytes), owner);
  modalCreated = 1;
  return 1;
}

// FUNCTION: IMPERIALISM 0x0049d450
int TModalDialogBase::DoModal() {
  if (modalCreated == 0) {
    PrepareAndCreateModalFromTemplate();
  }
  if (dialogCreatedSuccessfully != 0) {
    DWORD modalFlags = 4;
    if ((GetStyle() & 0x100) != 0) {
      modalFlags = 5;
    }
    RunModalLoop(modalFlags);
    SetWindowPos(0, 0, 0, 0, 0, 0x97);
  }
  if (ownerWasDisabled != 0) {
    ::EnableWindow(ownerWindow, TRUE);
  }
  if (ownerWindow != nullptr) {
    HWND activeWindow = ::GetActiveWindow();
    if (activeWindow == m_hWnd) {
      ::SetActiveWindow(ownerWindow);
    }
  }
  const int result = m_nModalResult;
  finalizeState = 1;
  return result;
}

// FUNCTION: IMPERIALISM 0x0049d510
void TModalDialogBase::CleanupModalCreateState() {
  if (modalCreated != 0) {
    DestroyWindow();
    PostModal();
    finalizeState = 0;
    dialogCreatedSuccessfully = 0;
    modalCreated = 0;
  }
}
