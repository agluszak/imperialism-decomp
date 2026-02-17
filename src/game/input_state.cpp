#include "game/input_state.h"

namespace {

static const unsigned int kGetActiveNationIdAddr = 0x00581260;
static const unsigned int kSetNationActionAddr = 0x00515e00;
static const unsigned int kGetMapOrderHeadAddr = 0x005505c0;
static const unsigned int kGlobalMapStatePtrAddr = 0x006a43d4;

typedef int(__cdecl *GetActiveNationIdFn)();
typedef void(__cdecl *SetNationActionFn)(int, int);
typedef int(__cdecl *GetMapOrderHeadFn)();
typedef short(__cdecl *VtableGetSlotFn)(void *);
typedef void(__cdecl *VtableSetUiFlagFn)(void *, int);

} // namespace

// FUNCTION: IMPERIALISM 0x0055fc40
void InputState::HandleKeyDown(int key_id)
{
  if ((active_key_mask & (1U << (key_id & 0x1f))) == 0) {
    active_key_mask |= (1U << (key_id & 0x1f));

    GetActiveNationIdFn get_active_nation_id =
        reinterpret_cast<GetActiveNationIdFn>(kGetActiveNationIdAddr);
    short slot_id = static_cast<short>(get_active_nation_id());

    bool slot_is_active = false;
    if ((active_key_mask & (1U << (slot_id & 0x1f))) == 0) {
      u32 slot_index = 0;
      while (slot_index < slot_count) {
        int *slot_entry_ptr = reinterpret_cast<int *>(slot_table_ptr + slot_index * 4);
        if (*reinterpret_cast<char *>(*slot_entry_ptr) == static_cast<char>(slot_id)) {
          slot_is_active = true;
          break;
        }
        slot_index += 1;
      }
    } else {
      slot_is_active = true;
    }

    if (slot_is_active) {
      int vtable = *reinterpret_cast<int *>(this);
      VtableSetUiFlagFn vfunc_set_ui_flag =
          reinterpret_cast<VtableSetUiFlagFn>(*reinterpret_cast<int *>(vtable + 0x58));
      VtableGetSlotFn vfunc_get_slot =
          reinterpret_cast<VtableGetSlotFn>(*reinterpret_cast<int *>(vtable + 0x50));
      SetNationActionFn set_nation_action =
          reinterpret_cast<SetNationActionFn>(kSetNationActionAddr);

      if (slot_id == static_cast<short>(key_id)) {
        vfunc_set_ui_flag(this, 1);

        int key_cycle = slot_id + 1;
        int slots_remaining = 6;
        while (slots_remaining != 0) {
          int nation_idx = key_cycle % 7;
          if ((active_key_mask & (1U << (nation_idx & 0x1f))) != 0) {
            short slot_handle = vfunc_get_slot(this);
            set_nation_action(static_cast<int>(slot_handle), nation_idx + 7);

            int global_map_state = *reinterpret_cast<int *>(kGlobalMapStatePtrAddr);
            int nation_state_ptr = *reinterpret_cast<int *>(global_map_state + 0xc);
            *reinterpret_cast<unsigned short *>(nation_state_ptr + 0x1a + slot_handle * 0x24) =
                0xffff;
          }
          key_cycle += 1;
          slots_remaining -= 1;
        }
      } else {
        int slot_handle = vfunc_get_slot(this);
        set_nation_action(slot_handle, static_cast<int>(slot_id) + 7);

        int global_map_state = *reinterpret_cast<int *>(kGlobalMapStatePtrAddr);
        int nation_state_ptr = *reinterpret_cast<int *>(global_map_state + 0xc);
        *reinterpret_cast<unsigned short *>(nation_state_ptr + 0x1a + slot_handle * 0x24) = 0xffff;
      }
    }
  }

  GetActiveNationIdFn get_active_nation_id =
      reinterpret_cast<GetActiveNationIdFn>(kGetActiveNationIdAddr);
  short active_slot = static_cast<short>(get_active_nation_id());
  if (active_slot == -1) {
    active_slot = static_cast<short>(get_active_nation_id());
  }

  if ((active_key_mask & (1U << (active_slot & 0x1f))) != 0) {
    GetMapOrderHeadFn get_map_order_head =
        reinterpret_cast<GetMapOrderHeadFn>(kGetMapOrderHeadAddr);
    int node = get_map_order_head();
    while (node != 0) {
      if ((*reinterpret_cast<void **>(node + 8) == this) &&
          (*reinterpret_cast<short *>(node + 0x14) == active_slot) &&
          (*reinterpret_cast<int *>(node + 0xc) == 0)) {
        int vtable = *reinterpret_cast<int *>(this);
        VtableSetUiFlagFn vfunc_set_ui_flag =
            reinterpret_cast<VtableSetUiFlagFn>(*reinterpret_cast<int *>(vtable + 0x58));
        vfunc_set_ui_flag(this, 1);
        return;
      }
      node = *reinterpret_cast<int *>(node + 0x24);
    }
  }

  {
    int vtable = *reinterpret_cast<int *>(this);
    VtableSetUiFlagFn vfunc_set_ui_flag =
        reinterpret_cast<VtableSetUiFlagFn>(*reinterpret_cast<int *>(vtable + 0x58));
    vfunc_set_ui_flag(this, 0);
  }
}
