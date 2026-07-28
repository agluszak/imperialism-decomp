#pragma once

#include "game/mfc.h"
#include "game/ui_core/TWindow.h"

// The two McAppUI window registries. Declared here rather than in the ui_core_globals
// umbrella because CList<TWindow*, TWindow*> needs TWindow complete (afxtempl.h's
// DestructElements names the element type's destructor), and only the four translation
// units that touch these registries should pay for that include.
//
// Both share one CList<TWindow*, TWindow*> specialization; its compiler-emitted members
// live at 0x00492510/0x00492550/0x004925e0/0x00492670 with vtable 0x0064b580.

// Live-view registry (base 0x006a1a40): every TWindow links itself in on construction and
// unlinks on teardown; CWMgrIterator sweeps it.
extern CList<TWindow*, TWindow*> g_LiveViewRegistry;

// Modal-window stack (base 0x006a1ac0): TWindow::ExecuteViewModalStateWithPushPopChain
// pushes the active window on entry and pops it on exit.
extern CList<TWindow*, TWindow*> g_ModalViewStack;
