// TArmyToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);

struct TradeMoveStepCluster;

namespace {

// GLOBAL: IMPERIALISM 0x667ad0
char g_vtblTArmyToolbar;
// GLOBAL: IMPERIALISM 0x6630d0
char g_pClassDescTArmyToolbar;

struct ArmyToolbarState {
  void* vftable;
  char pad_04[0x88];
};

class RuntimeBridge {
public:
  static __inline void ConstructTUberClusterBaseState(TradeMoveStepCluster* self) {
    reinterpret_cast<void(__fastcall*)(TradeMoveStepCluster*)>(::ConstructTUberClusterBaseState)(
        self);
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058de40
ArmyToolbarState* __cdecl CreateTArmyToolbarInstance(void) {
  ArmyToolbarState* toolbar =
      reinterpret_cast<ArmyToolbarState*>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    RuntimeBridge::ConstructTUberClusterBaseState(reinterpret_cast<TradeMoveStepCluster*>(toolbar));
    toolbar->vftable = reinterpret_cast<void*>(&g_vtblTArmyToolbar);
  }
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058dec0
void* __cdecl GetTArmyToolbarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTArmyToolbar);
}

// FUNCTION: IMPERIALISM 0x0058dee0
ArmyToolbarState* __fastcall ConstructTArmyToolbarBaseState(ArmyToolbarState* toolbar) {
  RuntimeBridge::ConstructTUberClusterBaseState(reinterpret_cast<TradeMoveStepCluster*>(toolbar));
  toolbar->vftable = reinterpret_cast<void*>(&g_vtblTArmyToolbar);
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058df10
ArmyToolbarState* __fastcall DestructTArmyToolbarAndMaybeFree(ArmyToolbarState* toolbar,
                                                              int unusedEdx,
                                                              unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)toolbar);
  }
  return toolbar;
}
