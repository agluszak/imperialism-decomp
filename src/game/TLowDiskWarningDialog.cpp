#include "game/TModalTemplateDialog.h"

#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x005e1bc0
TLowDiskWarningDialog::TLowDiskWarningDialog(void* initParam)
    : TModalTemplateDialog(0x98, static_cast<CWnd*>(initParam)), promptText() {
  SetPromptText(reinterpret_cast<LPCSTR>(g_szEmptyString));
}

void TLowDiskWarningDialog::SetPromptText(LPCSTR text) {
  promptText = text;
}
