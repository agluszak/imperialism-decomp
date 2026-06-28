#pragma once

#include "decomp_types.h"

undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode);
