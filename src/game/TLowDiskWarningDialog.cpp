#include "game/TModalTemplateDialog.h"

extern "C" char g_szEmptyString[];

// FUNCTION: IMPERIALISM 0x005e1bc0
TLowDiskWarningDialog::TLowDiskWarningDialog(void* initParam) {
  InitializeDialogTemplateFromId(0x98, initParam);
  modalCreated = 0;
  field5c = 0;
  hasCommandTagResource = 0;
  commandTagResourceByte = 0;
  padding_65_to_67[0] = 0;
  padding_65_to_67[1] = 0;
  padding_65_to_67[2] = 0;
  SetPromptText(reinterpret_cast<LPCSTR>(g_szEmptyString));
}

void TLowDiskWarningDialog::SetPromptText(LPCSTR text) {
  promptText = text;
}
