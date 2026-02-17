#include "game/config.h"

namespace {

static const unsigned int kInitConfigRuntimeThunkAddr = 0x0048a100;
static const unsigned int kCallCallbackRepeatedlyAddr = 0x005e8c50;
static const unsigned int kInitSharedStringRefAddr = 0x00605797;
static const unsigned int kConfigCtorCallbackAddr = 0x00405209;
static const unsigned int kConfigArrayCallbackAddr = 0x004b0970;
static const unsigned int kConfigVtableAddr = 0x0065c030;

typedef void(__cdecl *InitConfigRuntimeThunkFn)();
typedef void(__stdcall *CallCallbackRepeatedlyFn)(void *, unsigned int, int, void *);
typedef int *(__cdecl *InitSharedStringRefFn)(int *);

} // namespace

// FUNCTION: IMPERIALISM 0x00405529
int *Config::InitDefaults()
{
  InitConfigRuntimeThunkFn init_config_runtime_thunk =
      reinterpret_cast<InitConfigRuntimeThunkFn>(kInitConfigRuntimeThunkAddr);
  init_config_runtime_thunk();

  CallCallbackRepeatedlyFn call_callback_repeatedly =
      reinterpret_cast<CallCallbackRepeatedlyFn>(kCallCallbackRepeatedlyAddr);
  call_callback_repeatedly(callback_block_20, 8, 4, reinterpret_cast<void *>(kConfigCtorCallbackAddr));

  InitSharedStringRefFn init_shared_string_ref =
      reinterpret_cast<InitSharedStringRefFn>(kInitSharedStringRefAddr);
  init_shared_string_ref(&shared_ref_74);

  call_callback_repeatedly(callback_block_78, 4, 7, reinterpret_cast<void *>(kConfigArrayCallbackAddr));
  call_callback_repeatedly(callback_block_94, 4, 7, reinterpret_cast<void *>(kConfigArrayCallbackAddr));

  init_shared_string_ref(&shared_ref_b0);
  init_shared_string_ref(&shared_ref_b4);
  init_shared_string_ref(&shared_ref_b8);

  vtable_ptr = reinterpret_cast<void *>(kConfigVtableAddr);
  field_40 = 0;
  field_6c = 0;
  field_70 = 0;
  field_d8 = 0x6e616461;
  field_f4 = 0;
  return reinterpret_cast<int *>(&vtable_ptr);
}
