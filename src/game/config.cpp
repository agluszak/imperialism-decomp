#include "game/config.h"

static const unsigned int g_addrInitUiResourceEntryBaseHeaderDefaults = 0x0048a100;
static const unsigned int g_addrCallCallbackRepeatedly = 0x005e8c50;
static const unsigned int g_addrInitializeSharedStringRefFromEmpty = 0x00605797;
static const unsigned int g_addrVtblTMultiplayerMgr = 0x0065c030;

typedef void(__cdecl *PFN_InitUiResourceEntryBaseHeaderDefaults)(void);
typedef void(__stdcall *PFN_CallCallbackRepeatedly)(int arg1, int arg2, int arg3, int arg4, int arg5);
typedef int *(__cdecl *PFN_InitializeSharedStringRefFromEmpty)(int *dst_ref_ptr);

// FUNCTION: IMPERIALISM 0x00405529
int *__fastcall Config::InitDefaults()
{
  PFN_InitUiResourceEntryBaseHeaderDefaults pfnInitUiResourceEntryBaseHeaderDefaults =
      (PFN_InitUiResourceEntryBaseHeaderDefaults)g_addrInitUiResourceEntryBaseHeaderDefaults;
  PFN_CallCallbackRepeatedly pfnCallCallbackRepeatedly =
      (PFN_CallCallbackRepeatedly)g_addrCallCallbackRepeatedly;
  PFN_InitializeSharedStringRefFromEmpty pfnInitializeSharedStringRefFromEmpty =
      (PFN_InitializeSharedStringRefFromEmpty)g_addrInitializeSharedStringRefFromEmpty;

  pfnInitUiResourceEntryBaseHeaderDefaults();
  pfnCallCallbackRepeatedly((int)&callback_block_20, 8, 4, 0x405209, 0x40208b);
  pfnInitializeSharedStringRefFromEmpty(&shared_ref_74);
  pfnCallCallbackRepeatedly((int)&callback_block_78, 4, 7, 0x404642, 0x405fa1);
  pfnCallCallbackRepeatedly((int)&callback_block_94, 4, 7, 0x404642, 0x405fa1);
  pfnInitializeSharedStringRefFromEmpty(&shared_ref_b0);
  pfnInitializeSharedStringRefFromEmpty(&shared_ref_b4);
  pfnInitializeSharedStringRefFromEmpty(&shared_ref_b8);
  vtable_ptr = (void *)g_addrVtblTMultiplayerMgr;
  field_40 = 0;
  field_6c = 0;
  field_70 = 0;
  field_d8 = 0x6e616461;
  field_f4 = 0;
  return (int *)&vtable_ptr;
}
