#include "game/TModalTemplateDialog.h"

// FUNCTION: IMPERIALISM 0x0047dfd0
TAutoResolutionDialog::TAutoResolutionDialog(void* initParam) {
  InitializeDialogTemplateFromId(0xfb, initParam);
  modalCreated = 0;
  field5c = 0;
  hasCommandTagResource = 0;
  commandTagResourceByte = 0;
  padding_65_to_67[0] = 0;
  padding_65_to_67[1] = 0;
  padding_65_to_67[2] = 0;
}
