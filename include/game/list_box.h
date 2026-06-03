#pragma once

#include "decomp_types.h"
#include "game/CDataExchange.h"
#include "game/string_shared.h"

#include <windows.h>

// MFC dialog data-exchange (DDX) helpers for list/combo-box controls. These
// exchange the selected item between the control and a CString (StringShared).
void __stdcall DDX_LBString(CDataExchange* pDX, undefined4 nIDC, StringShared* value);
void __stdcall DDX_LBStringExact(CDataExchange* pDX, undefined4 nIDC, StringShared* value);
