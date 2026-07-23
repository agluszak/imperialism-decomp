#pragma once

#include "decomp_types.h"

// One turn of the MFC idle/message pump: spins CWinThread::OnIdle until a message is
// pending or idling is exhausted, then dispatches one message via PumpMessage. This is
// the application event loop, not UI invalidation -- it only shared a file with the
// invalidation-flag helpers historically.
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode);
