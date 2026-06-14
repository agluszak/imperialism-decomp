#include "game/network_error_reporting.h"

#include "game/CString.h"
#include "game/ui_invalidation_guard.h"

#include <windows.h>

extern "C" {
extern int DAT_006a601c;
extern char g_szEmptyString[];
}
undefined4 thunk_AssignStringSharedRefAndReturnThis(void);
undefined4 thunk_RunControlStringProviderAndDispatchLocalizedMessage(void);

static bool IsBenignWNetManagerErrorCode(int errorCode) {
  if (errorCode < -0x7ff8fff1) {
    return errorCode == -0x7ff8fff2 || errorCode == -0x7fffbfff || errorCode == -0x7fffbffe ||
           errorCode == -0x7fffbffb;
  }
  if (errorCode < -0x7788fffa) {
    return errorCode == -0x7788fffb || errorCode == -0x7ff8ffa9;
  }
  if (errorCode < -0x7788ffeb) {
    return errorCode == -0x7788ffec || errorCode == -0x7788fff6;
  }
  if (errorCode < -0x7788ffd7) {
    return errorCode == -0x7788ffd8 || errorCode == -0x7788ffe2;
  }
  if (errorCode < -0x7788ffc3) {
    return errorCode == -0x7788ffc4 || errorCode == -0x7788ffce;
  }
  if (errorCode < -0x7788ffaf) {
    return errorCode == -0x7788ffb0 || errorCode == -0x7788ffba;
  }
  if (errorCode < -0x7788ff87) {
    return errorCode == -0x7788ff88 || errorCode == -0x7788ffa6;
  }
  if (errorCode < -0x7788ff69) {
    return errorCode == -0x7788ff6a || errorCode == -0x7788ff7e;
  }
  if (errorCode < -0x7788ff55) {
    return errorCode == -0x7788ff56 || errorCode == -0x7788ff60;
  }
  if (errorCode < -0x7788ff37) {
    return errorCode == -0x7788ff38 || errorCode == -0x7788ff42;
  }
  if (errorCode < -0x7788ff23) {
    return errorCode == -0x7788ff24 || errorCode == -0x7788ff2e;
  }
  if (errorCode < -0x7788ff0f) {
    return errorCode == -0x7788ff10 || errorCode == -0x7788ff1a;
  }
  if (errorCode < -0x7788fef1) {
    return errorCode == -0x7788fef2 || errorCode == -0x7788ff06;
  }
  if (errorCode < -0x7788fedd) {
    return errorCode == -0x7788fede || errorCode == -0x7788fee8;
  }
  if (errorCode < -0x7788fec9) {
    return errorCode == -0x7788feca || errorCode == -0x7788fed4;
  }
  if (errorCode < -0x7788fc0d) {
    return errorCode == -0x7788fc0e || errorCode == -0x7788fc18;
  }
  if (errorCode < -0x7788fbf9) {
    return errorCode == -0x7788fbfa || errorCode == -0x7788fc04;
  }
  if (errorCode < -0x7788fbe5) {
    return errorCode == -0x7788fbe6 || errorCode == -0x7788fbf0;
  }
  return errorCode == -0x7788fbd2 || errorCode == 0;
}

// FUNCTION: IMPERIALISM 0x005e34f0
void ReportWNetManagerErrorCodeAndNotifyUi(int errorCode) {
  CString scratchMessage(g_szEmptyString);
  CString formattedMessage;

  if (IsBenignWNetManagerErrorCode(errorCode)) {
    formattedMessage = CString(g_szEmptyString);
  } else {
    char errorText[16];
    wsprintfA(errorText, "%d", errorCode);
    formattedMessage = CString(errorText);
  }

  scratchMessage.AssignFromPtr(formattedMessage);
  thunk_AssignStringSharedRefAndReturnThis();
  thunk_RunControlStringProviderAndDispatchLocalizedMessage();
  if (DAT_006a601c == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
}
