#pragma once

#include "decomp_types.h"
#include "game/CDataExchange.h"
#include "game/CString.h"

// MFC dialog data-exchange (DDX) helpers for list/combo-box controls. These
// exchange the selected item between the control and MFC CString (our CString class).
void __stdcall DDX_LBString(CDataExchange* pDX, undefined4 nIDC, CString* value);
void __stdcall DDX_LBStringExact(CDataExchange* pDX, undefined4 nIDC, CString* value);
