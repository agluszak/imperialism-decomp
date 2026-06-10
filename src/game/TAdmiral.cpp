#include "game/TAdmiral.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" void* g_apTerrainTypeDescriptorTable[];
extern "C" TAdmiral* g_pNavySecondaryOrderListHead = 0;
extern "C" char g_pClassDescTAdmiral = 0;

extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

undefined4
thunk_GenerateMappedFlavorTextByNationSlotField0C(void);
undefined4
thunk_RemoveDuplicateNavySecondaryOrdersByDisplayName(void);
undefined4 CompareAnsiStringsWithMbcsAwareness(void);
// FUNCTION: IMPERIALISM 0x00551410
void* TAdmiral::GetTAdmiralClassNamePointer() {
  return &g_pClassDescTAdmiral;
}

// FUNCTION: IMPERIALISM 0x00551430
TAdmiral::TAdmiral(short terrainTypeIndex)
    : terrainType(terrainTypeIndex), field_8(0), displayName(), field_10(0),
      next(g_pNavySecondaryOrderListHead), prev(0) {
  g_pNavySecondaryOrderListHead = this;
  if (next != 0) {
    next->prev = this;
  }
  if (static_cast<unsigned short>(terrainType) != 0xffff) {
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

// FUNCTION: IMPERIALISM 0x00551580
TAdmiral::~TAdmiral() {
  *reinterpret_cast<void**>(this) = &PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;
}

// SYNTHETIC: IMPERIALISM 0x00551550
// TAdmiral::`scalar deleting destructor'
