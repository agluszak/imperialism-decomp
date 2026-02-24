// TArmyInfoView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

// GLOBAL: IMPERIALISM 0x668358
char g_vtblTArmyInfoView;
// GLOBAL: IMPERIALISM 0x663148
char g_pClassDescTArmyInfoView;

struct ArmyInfoViewState {
  void* vftable;
  char pad_04[0x8c];
};

class RuntimeBridge {
public:
  static __inline void ConstructPictureResourceEntryBase(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void DestructCityDialogSharedBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x00591500
ArmyInfoViewState* __cdecl CreateTArmyInfoViewInstance(void) {
  ArmyInfoViewState* view = reinterpret_cast<ArmyInfoViewState*>(AllocateWithFallbackHandler(0x90));
  if (view != 0) {
    RuntimeBridge::ConstructPictureResourceEntryBase(view);
    view->vftable = reinterpret_cast<void*>(&g_vtblTArmyInfoView);
  }
  return view;
}

// FUNCTION: IMPERIALISM 0x00591580
void* __cdecl GetTArmyInfoViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTArmyInfoView);
}

// FUNCTION: IMPERIALISM 0x005915a0
ArmyInfoViewState* __fastcall ConstructTArmyInfoViewBaseState(ArmyInfoViewState* view) {
  RuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void*>(&g_vtblTArmyInfoView);
  return view;
}

// FUNCTION: IMPERIALISM 0x005915d0
ArmyInfoViewState* __fastcall DestructTArmyInfoViewAndMaybeFree(ArmyInfoViewState* view,
                                                                int unusedEdx,
                                                                unsigned char freeSelfFlag) {
  (void)unusedEdx;
  RuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}
