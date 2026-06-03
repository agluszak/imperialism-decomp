#pragma once

#include "decomp_types.h"

// MFC CDataExchange: the dialog data-exchange (DDX/DDV) cursor passed to every
// DDX_* helper. m_bSaveAndValidate at +0 selects the transfer direction (0 =
// dialog->member on init, nonzero = member->dialog on save). Only that flag is
// modeled so far; the rest of the cursor is left opaque.
struct CDataExchange {
  int m_bSaveAndValidate;
};
