#include "game/list_box.h"

namespace {

static const unsigned int kGetControlWindowAddr = 0x006189dc;
static const unsigned int kEnsureSelectionAvailableAddr = 0x0060586d;
static const unsigned int kNormalizeItemDataAddr = 0x00605d99;
static const unsigned int kReleaseTempSharedRefAddr = 0x00605d71;

typedef HWND(__cdecl *GetControlWindowFn)(undefined4);
typedef void(__cdecl *EnsureSelectionAvailableFn)();
typedef LPARAM(__cdecl *NormalizeItemDataFn)(LRESULT);
typedef void(__cdecl *ReleaseTempSharedRefFn)(int);

} // namespace

// FUNCTION: IMPERIALISM 0x00618df2
void __stdcall ListBox::AddOrUpdateItemData(
    ListBoxItemCount *item_count_ptr,
    undefined4 control_id,
    LPARAM *item_data_ptr)
{
  GetControlWindowFn get_control_window =
      reinterpret_cast<GetControlWindowFn>(kGetControlWindowAddr);
  HWND listbox_hwnd = get_control_window(control_id);
  if (item_count_ptr->value == 0) {
    SendMessageA(listbox_hwnd, 0x18c, static_cast<WPARAM>(0xffffffff), *item_data_ptr);
  } else {
    WPARAM sel_index = SendMessageA(listbox_hwnd, 0x188, 0, 0);
    if (sel_index == static_cast<WPARAM>(0xffffffff)) {
      EnsureSelectionAvailableFn ensure_selection_available =
          reinterpret_cast<EnsureSelectionAvailableFn>(kEnsureSelectionAvailableAddr);
      ensure_selection_available();
    } else {
      LRESULT raw_item_data = SendMessageA(listbox_hwnd, 0x18a, sel_index, 0);
      NormalizeItemDataFn normalize_item_data =
          reinterpret_cast<NormalizeItemDataFn>(kNormalizeItemDataAddr);
      LPARAM normalized_item_data = normalize_item_data(raw_item_data);
      SendMessageA(listbox_hwnd, 0x189, sel_index, normalized_item_data);
    }

    ReleaseTempSharedRefFn release_temp_shared_ref =
        reinterpret_cast<ReleaseTempSharedRefFn>(kReleaseTempSharedRefAddr);
    release_temp_shared_ref(0xffffffff);
  }
}

// FUNCTION: IMPERIALISM 0x00618e72
void __stdcall SelectComboBoxItemByParam(
    int *state_flag,
    undefined4 owner_id,
    LPARAM *lparam_in)
{
  GetControlWindowFn get_control_window =
      reinterpret_cast<GetControlWindowFn>(kGetControlWindowAddr);
  HWND target_hwnd = get_control_window(owner_id);
  if (*state_flag == 0) {
    WPARAM item_index =
        SendMessageA(target_hwnd, 0x1a2, static_cast<WPARAM>(0xffffffff), *lparam_in);
    if (item_index != static_cast<WPARAM>(0xffffffff)) {
      SendMessageA(target_hwnd, 0x186, item_index, 0);
    }
  } else {
    ListBox::AddOrUpdateItemData(
        reinterpret_cast<ListBoxItemCount *>(state_flag), owner_id, lparam_in);
  }
}
