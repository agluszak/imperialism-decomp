#pragma once

#include "decomp_types.h"

undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);
void TemporarilyClearAndRestoreUiInvalidationFlag(const char* sourceFile, int line);
int __stdcall PumpUiMessagesAndBackgroundTasks(int nTaskPumpMode);
