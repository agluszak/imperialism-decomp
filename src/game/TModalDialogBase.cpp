// Manual decompilation file.

#include "game/TModalDialogBase.h"

#include "game/mfc.h"

namespace {

HWND ResolvePreModalOwner() {
  if (AfxGetApp() == nullptr || AfxGetApp()->m_pMainWnd == nullptr) {
    return nullptr;
  }
  return AfxGetApp()->m_pMainWnd->GetSafeHwnd();
}

} // namespace

// Destructors are compiler-generated (implicit) from real CDialog inheritance; the
// out-of-line anchor here gives the base its own vtable (0x0063e5a0).
TModalDialogBase::~TModalDialogBase() {}

// FUNCTION: IMPERIALISM 0x0049d360
int TModalDialogBase::PrepareAndCreateModalFromTemplate() {
  void* templateBytes = const_cast<void*>(reinterpret_cast<const void*>(m_lpDialogTemplate));
  loadedResource = m_hDialogTemplate;
  const UINT templateId = static_cast<UINT>(reinterpret_cast<DWORD>(m_lpszTemplateName));
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

  ownerWindow = ResolvePreModalOwner();
  ownerWasDisabled = 0;
  if (ownerWindow != nullptr && ::IsWindowEnabled(ownerWindow)) {
    ::EnableWindow(ownerWindow, FALSE);
    ownerWasDisabled = 1;
  }
  createdDialog = ::CreateDialogIndirectA(
      AfxGetInstanceHandle(), static_cast<LPCDLGTEMPLATE>(templateBytes), ownerWindow, nullptr);
  modalCreated = 1;
  return createdDialog != nullptr ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x0049d450
int TModalDialogBase::DoModal() {
  if (ownerWasDisabled != 0) {
    ::EnableWindow(ownerWindow, TRUE);
  }
  if (ownerWindow != nullptr) {
    HWND activeWindow = ::GetActiveWindow();
    if (activeWindow == createdDialog) {
      ::SetActiveWindow(ownerWindow);
    }
  }
  // The dialog result the game reads back is the CWnd-region word at this+0x2c, set by
  // the modal loop before the owner-focus restore.
  const int result = reinterpret_cast<const int*>(this)[0x2c / 4];
  finalizeState = 1;
  return result;
}

// FUNCTION: IMPERIALISM 0x0049d510
void TModalDialogBase::CleanupModalCreateState() {
  if (modalCreated != 0) {
    DestroyWindow();
    PostModal();
    finalizeState = 0;
    createdDialog = nullptr;
    modalCreated = 0;
  }
}
