#pragma once

#include "game/mfc.h"
#include "game/ui_core/TWindow.h"

// The two McAppUI window registries live in TWindow.h: retail expands the
// registry link-in inline at every TWindow subclass construction site, so the
// declarations must be visible wherever TWindow.h is. This header remains as
// the canonical include for consumers that only need the registries.
//
// Both share one CList<TWindow*, TWindow*> specialization; its compiler-emitted
// members live at 0x00492510/0x00492550/0x004925e0/0x00492670 with vtable
// 0x0064b580.
