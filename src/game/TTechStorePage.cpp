#include "game/TTechStorePage.h"

// TTechStorePage's vtable (0x645ca8) is a TPageView clone: only slot 0x00
// (GetRuntimeClass, via IMPLEMENT_DYNCREATE) and the scalar deleting destructor
// differ; every other slot is inherited unchanged from TPageView. The functions
// that the auto-recovery previously attributed here (0x479440/0x4796xx and the
// 0x606xxx/0x610xxx/0x611xxx MFC addresses) belong to the adjacent TScroller
// vtable / MFC library, not to TTechStorePage.

// SYNTHETIC: IMPERIALISM 0x004600f0
// TTechStorePage::`scalar deleting destructor'
TTechStorePage::~TTechStorePage() {}

// SYNTHETIC: IMPERIALISM 0x005b0e70
// TTechStorePage::CreateObject

IMPLEMENT_DYNCREATE(TTechStorePage, TPageView)

TTechStorePage::TTechStorePage() {}
