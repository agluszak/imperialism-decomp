#include "game/TAutoResolutionDialog.h"

#include <stddef.h>

namespace {

#define TG_LAYOUT_ASSERT(name, expr) typedef char name[(expr) ? 1 : -1]

TG_LAYOUT_ASSERT(TModalTemplateDialogBase_Size_0x74, sizeof(TModalTemplateDialogBase) == 0x74);
TG_LAYOUT_ASSERT(TAutoResolutionDialog_Offset_primaryDialogControl_0x74,
                 offsetof(TAutoResolutionDialog, primaryDialogControl) == 0x74);
TG_LAYOUT_ASSERT(TAutoResolutionDialog_Offset_secondaryDialogControl_0xb0,
                 offsetof(TAutoResolutionDialog, secondaryDialogControl) == 0xb0);
TG_LAYOUT_ASSERT(TAutoResolutionDialog_Offset_autoResolutionCheckState_0xec,
                 offsetof(TAutoResolutionDialog, autoResolutionCheckState) == 0xec);
TG_LAYOUT_ASSERT(TAutoResolutionDialog_Size_0xf0, sizeof(TAutoResolutionDialog) == 0xf0);
TG_LAYOUT_ASSERT(CWnd_EmbedSize_0x3c, sizeof(CWnd) == 0x3c);

#undef TG_LAYOUT_ASSERT

} // namespace

// FUNCTION: IMPERIALISM 0x0047dfd0
TAutoResolutionDialog::TAutoResolutionDialog(void* initParam)
    : TModalTemplateDialogBase(), primaryDialogControl(), secondaryDialogControl(),
      autoResolutionCheckState(0) {
  InitializeDialogTemplateFromId(0xfb, initParam);
  field5c = 0;
  hasCommandTagResource = 0;
  commandTagResourceByte = 0;
  padding_65_to_67[0] = 0;
  padding_65_to_67[1] = 0;
  padding_65_to_67[2] = 0;
}

// FUNCTION: IMPERIALISM 0x0047e0c0
BOOL TAutoResolutionDialog::UpdateData(BOOL saveAndValidate) {
  if (reinterpret_cast<HWND>(hasCommandTagResource) == nullptr) {
    return FALSE;
  }
  CDialog dialog;
  dialog.Attach(reinterpret_cast<HWND>(hasCommandTagResource));
  CDataExchange dx(&dialog, saveAndValidate);
  DDX_Control(&dx, 0x434, primaryDialogControl);
  DDX_Check(&dx, 0x434, autoResolutionCheckState);
  dialog.Detach();
  return TRUE;
}
