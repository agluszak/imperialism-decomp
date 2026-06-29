#include "game/network_error_reporting.h"
#include "game/global_data_tables.h"

#include "game/TViewMgr.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_invalidation_guard.h"

extern "C" {
extern int DAT_006a601c;
}

static const char kDirectPlayErrorTitle[] = "DirectPlay Error";
static const char kNetworkErrorGeneric[] = "A network error has occurred.";
static const char kDirectPlayOk[] = "DirectPlay OK";

static const char* LookupDirectPlayErrorDetailText(int errorCode) {
  if (errorCode < -0x7ff8fff1) {
    if (errorCode == -0x7ff8fff2) {
      return "Not enough memory available.";
    }
    if (errorCode == -0x7fffbfff) {
      return "This function is not supported on this system.";
    }
    if (errorCode == -0x7fffbffe) {
      return "No such interface supported.";
    }
    if (errorCode == -0x7fffbffb) {
      return "An undefined error code was returned from a DirectPlay function.";
    }
    return 0;
  }
  if (errorCode < -0x7788fffa) {
    if (errorCode == -0x7788fffb) {
      return "This object is already initialized.";
    }
    if (errorCode == -0x7ff8ffa9) {
      return "One or more parameters were invalid.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffeb) {
    if (errorCode == -0x7788ffec) {
      return "There are active players in the session.";
    }
    if (errorCode == -0x7788fff6) {
      return "Access to the object is denied.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffd7) {
    if (errorCode == -0x7788ffd8) {
      return "Can't add player.";
    }
    if (errorCode == -0x7788ffe2) {
      return "The buffer supplied is too small.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffc3) {
    if (errorCode == -0x7788ffc4) {
      return "Can't create player.";
    }
    if (errorCode == -0x7788ffce) {
      return "Can't create group.";
    }
    return 0;
  }
  if (errorCode < -0x7788ffaf) {
    if (errorCode == -0x7788ffb0) {
      return "The capabilities requested are not yet available.";
    }
    if (errorCode == -0x7788ffba) {
      return "Can't create session.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff87) {
    if (errorCode == -0x7788ff88) {
      return "Invalid flags were specified.";
    }
    if (errorCode == -0x7788ffa6) {
      return "An exception occurred.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff69) {
    if (errorCode == -0x7788ff6a) {
      return "Invalid player.";
    }
    if (errorCode == -0x7788ff7e) {
      return "Invalid object.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff55) {
    if (errorCode == -0x7788ff56) {
      return "No connection.";
    }
    if (errorCode == -0x7788ff60) {
      return "The required capabilities are not available.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff37) {
    if (errorCode == -0x7788ff38) {
      return "No name server found.";
    }
    if (errorCode == -0x7788ff42) {
      return "There are no messages waiting.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff23) {
    if (errorCode == -0x7788ff24) {
      return "There are no sessions available.";
    }
    if (errorCode == -0x7788ff2e) {
      return "There are no players available.";
    }
    return 0;
  }
  if (errorCode < -0x7788ff0f) {
    if (errorCode == -0x7788ff10) {
      return "The operation timed out.";
    }
    if (errorCode == -0x7788ff1a) {
      return "The message is too large to send.";
    }
    return 0;
  }
  if (errorCode < -0x7788fef1) {
    if (errorCode == -0x7788fef2) {
      return "The message queue is full.";
    }
    if (errorCode == -0x7788ff06) {
      return "The service is unavailable.";
    }
    return 0;
  }
  if (errorCode < -0x7788fedd) {
    if (errorCode == -0x7788fede) {
      return "Can't create server.";
    }
    if (errorCode == -0x7788fee8) {
      return "The user canceled the operation.";
    }
    return 0;
  }
  if (errorCode < -0x7788fec9) {
    if (errorCode == -0x7788feca) {
      return "The session was lost.";
    }
    if (errorCode == -0x7788fed4) {
      return "The player was lost.";
    }
    return 0;
  }
  if (errorCode < -0x7788fc0d) {
    if (errorCode == -0x7788fc0e) {
      return "Can't create process.";
    }
    if (errorCode == -0x7788fc18) {
      return "The buffer is too large.";
    }
    return 0;
  }
  if (errorCode < -0x7788fbf9) {
    if (errorCode == -0x7788fbfa) {
      return "Invalid interface.";
    }
    if (errorCode == -0x7788fc04) {
      return "The application is not started.";
    }
    return 0;
  }
  if (errorCode < -0x7788fbe5) {
    if (errorCode == -0x7788fbe6) {
      return "Unknown application.";
    }
    if (errorCode == -0x7788fbf0) {
      return "No service provider available.";
    }
    return 0;
  }
  if (errorCode == -0x7788fbd2) {
    return "Not lobbied.";
  }
  if (errorCode == 0) {
    return kDirectPlayOk;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e34f0
void ReportWNetManagerErrorCodeAndNotifyUi(int errorCode) {
  CString message(kDirectPlayErrorTitle);
  const char* detailText = LookupDirectPlayErrorDetailText(errorCode);
  if (detailText == 0) {
    CString genericMessage(kNetworkErrorGeneric);
    message = genericMessage;
  } else {
    message += detailText;
  }

  reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
      ->RunControlStringProviderAndDispatchLocalizedMessage(&message);
  if (DAT_006a601c == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
}
