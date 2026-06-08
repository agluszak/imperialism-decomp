#include "game/TPtrList.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

extern "C" {
char g_pClassDescTPtrList = 0;
}

#if defined(_MSC_VER)
#pragma optimize("yt", on)
#endif

// FUNCTION: IMPERIALISM 0x00488510
void* TPtrList::GetTPtrListClassNamePointer() {
  return &g_pClassDescTPtrList;
}

// FUNCTION: IMPERIALISM 0x004885d0
void TPtrList::ConstructTPtrListBaseState(int ownerContext) {
  new (&this->listState) CPtrList(ownerContext);
}

// Destructor is compiler-generated; the implicit ~TPtrList destroys the embedded
// listState (CPtrList), which is what the scalar deleting destructor does.
// SYNTHETIC: IMPERIALISM 0x004885f0
// TPtrList::`scalar deleting destructor'
