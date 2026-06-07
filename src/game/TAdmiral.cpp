#include "game/TAdmiral.h"

// EH ctor; the original is FPO (esp-relative) despite the fs:[0] frame — force /Oy
// (heuristic 88) so the argument/state loads match.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" void* g_apTerrainTypeDescriptorTable[];
extern "C" TAdmiral* g_pNavySecondaryOrderListHead = 0;

// Generic-form external thunks (rule 9), typed-cast at the callsite.
undefined4 thunk_GenerateMappedFlavorTextByNationSlotField0C(void);   // 0x0040231a (descriptor thiscall)
undefined4 thunk_RemoveDuplicateNavySecondaryOrdersByDisplayName(void); // 0x004058f3 (this thiscall)
undefined4 CompareAnsiStringsWithMbcsAwareness(void);                 // 0x005e7980 (int __cdecl(int,int))

// Real EH ctor. The scalar fields + the CString member displayName are member-initializers
// (heuristic 92) so they emit in declaration order before the body, with the base
// RefCountedObjectBase vptr (0x006485c0) then the derived vptr (0x0065c498, owned by the
// // VTABLE annotation) written around them. `next(g_pNavySecondaryOrderListHead)` captures
// the old list head before the body re-points the head at this node.
// FUNCTION: IMPERIALISM 0x00551430
TAdmiral::TAdmiral(short terrainTypeIndex)
    : terrainType(terrainTypeIndex),
      field_8(0),
      displayName(),
      field_10(0),
      next(g_pNavySecondaryOrderListHead),
      prev(0) {
  g_pNavySecondaryOrderListHead = this;
  if (next != 0) {
    next->prev = this;
  }
  if (static_cast<unsigned short>(terrainType) != 0xffff) {
    // thiscall on the terrain descriptor (ecx) with the CString out-param on the stack;
    // no class is modeled for the descriptor, so this stays a __fastcall bridge (the
    // dummy edx is the documented allowance for an unavoidable free-function thiscall).
    reinterpret_cast<void(__fastcall*)(void*, int, CString*)>(
        thunk_GenerateMappedFlavorTextByNationSlotField0C)(
        g_apTerrainTypeDescriptorTable[terrainType], 0, &displayName);
    for (TAdmiral* node = g_pNavySecondaryOrderListHead; node != 0; node = node->next) {
      if (node == this) {
        continue;
      }
      int sameDisplayName =
          (reinterpret_cast<int(__cdecl*)(int, int)>(CompareAnsiStringsWithMbcsAwareness)(
               node->displayName.data_ptr, this->displayName.data_ptr) == 0);
      if (sameDisplayName) {
        reinterpret_cast<void(__fastcall*)(TAdmiral*)>(
            thunk_RemoveDuplicateNavySecondaryOrdersByDisplayName)(this);
      }
    }
  }
}
