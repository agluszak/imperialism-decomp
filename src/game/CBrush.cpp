#include "game/CBrush.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

CGdiObject::CGdiObject() : CObject(), gdiHandle(0) {}

CBrush::CBrush() : CGdiObject() {}

bool CBrush::AttachRegionHandleToClipStateAndRegister() {
  typedef bool(__fastcall * AttachRegionHandleFn)(CBrush* self, int unusedEdx);
  return reinterpret_cast<AttachRegionHandleFn>(0x00613a4c)(this, 0);
}

// Destructors are compiler-generated (implicit virtual dtor).
// SYNTHETIC: IMPERIALISM 0x005e6ea2
// CBrush::`scalar deleting destructor'
